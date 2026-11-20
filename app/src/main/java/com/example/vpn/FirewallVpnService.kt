package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import com.example.FirewallApplication
import com.example.MainActivity
import com.example.R
import com.example.data.local.CaptureSessionEntity
import com.example.engine.network.IdsConfig
import com.example.engine.network.PacketParser
import com.example.engine.network.ParsedPacket
import com.example.engine.network.PcapngWriter
import com.example.engine.network.TransportProtocol
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class FirewallVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.example.vpn.ACTION_START"
        const val ACTION_STOP = "com.example.vpn.ACTION_STOP"
        const val ACTION_START_PCAP = "com.example.vpn.ACTION_START_PCAP"
        const val ACTION_STOP_PCAP = "com.example.vpn.ACTION_STOP_PCAP"
        const val ACTION_REFRESH_RULES = "com.example.vpn.ACTION_REFRESH_RULES"

        private const val CHANNEL_ID = "adf_vpn_shield"
        private const val NOTIFICATION_ID = 4401
        private const val VPN_MTU = 1500
        private const val VPN_IPV4_ADDRESS = "10.215.0.1"
        private const val VPN_IPV6_ADDRESS = "fd00:10:215::1"
        private const val INVALID_UID = -1
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val packetIdGen = AtomicLong(1L)
    private val uidLabelCache = ConcurrentHashMap<Int, String>()
    private val udpSessions = ConcurrentHashMap<String, UdpRelaySession>()
    private val tcpSessions = ConcurrentHashMap<String, TcpRelaySession>()
    private val tunWriteLock = Any()

    private val pcapngWriter = PcapngWriter(ringCapacity = 2048)

    private var tunInterface: ParcelFileDescriptor? = null
    private var tunOutput: FileOutputStream? = null
    private var packetLoopJob: Job? = null
    private var cleanupJob: Job? = null
    private var observerJob: Job? = null

    private val appContainer by lazy { (application as FirewallApplication).container }

    private data class UdpRelaySession(
        val key: String,
        val channel: DatagramChannel,
        val clientIp: ByteArray,
        val clientPort: Int,
        val remoteIp: ByteArray,
        val remotePort: Int,
        val appUid: Int,
        val appLabel: String,
        @Volatile var lastActiveAt: Long,
        val readerJob: Job
    )

    private data class TcpRelaySession(
        val key: String,
        val channel: SocketChannel,
        val clientIp: ByteArray,
        val clientPort: Int,
        val remoteIp: ByteArray,
        val remotePort: Int,
        val appUid: Int,
        val appLabel: String,
        @Volatile var serverSeq: Long,
        @Volatile var clientNextSeq: Long,
        @Volatile var lastActiveAt: Long,
        var readerJob: Job? = null
    )

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpnEngine()
                return START_NOT_STICKY
            }
            ACTION_START_PCAP -> {
                serviceScope.launch { startPcapRecording() }
                return START_STICKY
            }
            ACTION_STOP_PCAP -> {
                serviceScope.launch { stopPcapRecording() }
                return START_STICKY
            }
            ACTION_REFRESH_RULES -> {
                serviceScope.launch { syncRulesAndFeeds() }
                return START_STICKY
            }
            else -> {
                startVpnEngine()
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        stopVpnEngine()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpnEngine()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startVpnEngine() {
        if (tunInterface != null) return
        appContainer.telemetryBus.setVpnState(VpnEngineState.STARTING)

        createNotificationChannel()
        val notification = buildNotification("Initializing TUN interface...")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        try {
            val builder = Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(VPN_MTU)
                .addAddress(VPN_IPV4_ADDRESS, 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("9.9.9.9")

            runCatching {
                builder.addAddress(VPN_IPV6_ADDRESS, 64)
                builder.addRoute("::", 0)
            }
            // Exclude our own package so protected upstream sockets never loop back
            runCatching { builder.addDisallowedApplication(packageName) }

            val pfd = builder.establish()
            if (pfd == null) {
                appContainer.telemetryBus.setVpnState(
                    VpnEngineState.ERROR,
                    "Android VPN interface could not be established (revoked or occupied)."
                )
                stopSelf()
                return
            }

            tunInterface = pfd
            tunOutput = FileOutputStream(pfd.fileDescriptor)
            appContainer.telemetryBus.setVpnState(VpnEngineState.RUNNING)
            updateNotification("Firewall & Inline IDS Active • TUN Armed")

            startRuleObservers()
            startPacketLoop(pfd)
            startSessionCleanupLoop()
        } catch (e: Exception) {
            appContainer.telemetryBus.setVpnState(
                VpnEngineState.ERROR,
                "VPN start failed: ${e.message ?: e.javaClass.simpleName}"
            )
            stopVpnEngine()
        }
    }

    private fun startRuleObservers() {
        observerJob?.cancel()
        observerJob = serviceScope.launch {
            appContainer.repository.ensureSeeded()
            syncRulesAndFeeds()

            launch {
                appContainer.preferences.settingsFlow.collect { settings ->
                    appContainer.idsEngine.updateConfig(
                        IdsConfig(
                            dnsPhishingEnabled = settings.idsDnsPhishingEnabled,
                            heuristicsEnabled = settings.idsHeuristicsEnabled,
                            behavioralScanEnabled = settings.idsBehavioralScanEnabled,
                            httpDpiEnabled = settings.idsHttpDpiEnabled
                        )
                    )
                    val activeRules = appContainer.repository.getActiveRulesSnapshot()
                    appContainer.ruleEngine.updateRules(activeRules, settings.defaultBlockAllMode)
                    if (settings.autoRecordPcapOnVpnStart && !pcapngWriter.isRecording()) {
                        startPcapRecording()
                    }
                }
            }

            launch {
                appContainer.repository.allRules.collect { rules ->
                    val blockAll = appContainer.latestDefaultBlockAll.get()
                    appContainer.ruleEngine.updateRules(rules, blockAll)
                }
            }

            launch {
                appContainer.repository.threatFeedEntries.collect { entries ->
                    appContainer.idsEngine.updateThreatFeed(
                        entries.filter { it.enabled }.map { it.indicator }
                    )
                }
            }
        }
    }

    private suspend fun syncRulesAndFeeds() {
        val rules = appContainer.repository.getActiveRulesSnapshot()
        appContainer.ruleEngine.updateRules(rules, appContainer.latestDefaultBlockAll.get())
        val indicators = appContainer.repository.getEnabledThreatIndicators()
        appContainer.idsEngine.updateThreatFeed(indicators)
    }

    private fun startPacketLoop(pfd: ParcelFileDescriptor) {
        packetLoopJob?.cancel()
        packetLoopJob = serviceScope.launch(Dispatchers.IO) {
            val input = FileInputStream(pfd.fileDescriptor)
            val rawBuf = ByteArray(32_768)
            val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

            while (isActive && tunInterface != null) {
                val readLen = try {
                    input.read(rawBuf)
                } catch (_: Exception) {
                    break
                }
                if (readLen <= 0) continue

                val parsed = PacketParser.parse(rawBuf, readLen) ?: continue
                val appUid = resolveOwnerUid(connectivityManager, parsed)
                val appLabel = resolveUidLabel(appUid)

                // 1. Evaluate Firewall Rules BEFORE Forwarding
                val verdict = appContainer.ruleEngine.evaluate(parsed, appUid)
                val verdictLabel = if (verdict.allowed) "ALLOW" else "BLOCK"

                if (verdict.matchedRuleType != null && verdict.matchedTarget != null) {
                    serviceScope.launch {
                        runCatching {
                            appContainer.repository.incrementRuleHit(
                                verdict.matchedRuleType,
                                verdict.matchedTarget
                            )
                        }
                    }
                }

                // 2. Simultaneous PCAPNG Tee (lock-free bounded ring buffer)
                pcapngWriter.offerPacket(
                    rawBytes = rawBuf,
                    length = readLen,
                    uid = appUid,
                    appLabel = appLabel,
                    verdict = verdictLabel,
                    host = parsed.domainOrSni
                )

                // 3. Inline IDS Inspection (DNS/SNI Phishing, Heuristics, Scan/Fuzzing, HTTP DPI)
                val alerts = appContainer.idsEngine.inspect(parsed, appUid, appLabel)
                if (alerts.isNotEmpty()) {
                    serviceScope.launch {
                        for (alert in alerts) {
                            runCatching { appContainer.repository.insertAlert(alert) }
                        }
                    }
                }

                // 4. Emit Live Telemetry Event
                val tlsNote = parsed.tlsInfo?.let { "${it.tlsVersionLabel} JA3:${it.ja3Hash.take(10)}" }
                val inspectionNote = when {
                    alerts.isNotEmpty() -> "IDS: ${alerts.first().title}"
                    parsed.tlsInfo != null -> "TLS Metadata Only (Encrypted Payload)"
                    parsed.httpInfo != null -> "HTTP Cleartext DPI (${parsed.httpInfo.method ?: parsed.httpInfo.statusCode})"
                    parsed.dnsQueryDomain != null -> "DNS Query: ${parsed.dnsQueryDomain}"
                    else -> verdict.reason
                }

                appContainer.telemetryBus.recordPacket(
                    event = LivePacketEvent(
                        id = packetIdGen.getAndIncrement(),
                        timestamp = System.currentTimeMillis(),
                        direction = "TX",
                        protocol = parsed.protocol.label,
                        srcIp = parsed.srcIp,
                        srcPort = parsed.srcPort,
                        dstIp = parsed.dstIp,
                        dstPort = parsed.dstPort,
                        byteLength = readLen,
                        appUid = appUid,
                        appLabel = appLabel,
                        allowed = verdict.allowed,
                        ruleReason = verdict.reason,
                        domainOrSni = parsed.domainOrSni,
                        tlsSummary = tlsNote,
                        inspectionNote = inspectionNote,
                        hexPreview = PacketParser.toHexPreview(rawBuf, readLen)
                    ),
                    isDns = parsed.dnsQueryDomain != null,
                    isTls = parsed.tlsInfo != null,
                    newAlerts = alerts.size
                )

                // 5. Enforce Verdict: Drop Blocked Traffic or Forward Allowed Traffic via protect()-ed Sockets
                if (!verdict.allowed) {
                    if (parsed.ipVersion == 4 && parsed.protocol == TransportProtocol.TCP && parsed.isTcpSyn) {
                        val rst = PacketParser.buildIpv4TcpPacket(
                            srcIp = parsed.dstIpBytes,
                            dstIp = parsed.srcIpBytes,
                            srcPort = parsed.dstPort,
                            dstPort = parsed.srcPort,
                            seq = 0L,
                            ack = parsed.tcpSeq + 1L,
                            flags = 0x14 // RST + ACK
                        )
                        writeToTun(rst)
                    }
                    continue
                }

                if (parsed.ipVersion == 4 && !parsed.isMalformed) {
                    when (parsed.protocol) {
                        TransportProtocol.UDP -> forwardUdpIpv4(parsed, rawBuf, appUid, appLabel)
                        TransportProtocol.TCP -> forwardTcpIpv4(parsed, rawBuf, appUid, appLabel)
                        else -> Unit
                    }
                }
            }
        }
    }

    private fun resolveOwnerUid(cm: ConnectivityManager, packet: ParsedPacket): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return INVALID_UID
        val osProto = when (packet.protocol) {
            TransportProtocol.TCP -> OsConstants.IPPROTO_TCP
            TransportProtocol.UDP -> OsConstants.IPPROTO_UDP
            else -> return INVALID_UID
        }
        return try {
            val local = InetSocketAddress(InetAddress.getByAddress(packet.srcIpBytes), packet.srcPort)
            val remote = InetSocketAddress(InetAddress.getByAddress(packet.dstIpBytes), packet.dstPort)
            cm.getConnectionOwnerUid(osProto, local, remote)
        } catch (_: Exception) {
            INVALID_UID
        }
    }

    private fun resolveUidLabel(uid: Int): String {
        if (uid < 0) return "Kernel / Unattributed"
        return uidLabelCache.computeIfAbsent(uid) {
            when (uid) {
                0 -> "root (UID 0)"
                1000 -> "Android System (1000)"
                else -> {
                    val pkgs = runCatching { packageManager.getPackagesForUid(uid) }.getOrNull()
                    val pkg = pkgs?.firstOrNull()
                    if (pkg != null) {
                        runCatching {
                            val ai = packageManager.getApplicationInfo(pkg, 0)
                            packageManager.getApplicationLabel(ai).toString()
                        }.getOrDefault(pkg)
                    } else {
                        "UID $uid"
                    }
                }
            }
        }
    }

    private fun forwardUdpIpv4(packet: ParsedPacket, raw: ByteArray, appUid: Int, appLabel: String) {
        if (packet.payloadLength <= 0) return
        val key = "${packet.srcIp}:${packet.srcPort}->${packet.dstIp}:${packet.dstPort}"
        val now = System.currentTimeMillis()
        val session = udpSessions[key] ?: createUdpSession(key, packet, appUid, appLabel, now) ?: return
        session.lastActiveAt = now
        try {
            val payloadBuf = ByteBuffer.wrap(raw, packet.payloadOffset, packet.payloadLength)
            session.channel.write(payloadBuf)
        } catch (_: Exception) {
            closeUdpSession(key)
        }
    }

    private fun createUdpSession(
        key: String,
        packet: ParsedPacket,
        appUid: Int,
        appLabel: String,
        now: Long
    ): UdpRelaySession? {
        return try {
            val channel = DatagramChannel.open()
            if (!protect(channel.socket())) {
                channel.close()
                return null
            }
            channel.connect(InetSocketAddress(InetAddress.getByAddress(packet.dstIpBytes), packet.dstPort))
            val clientIpCopy = packet.srcIpBytes.copyOf()
            val remoteIpCopy = packet.dstIpBytes.copyOf()
            val readerJob = serviceScope.launch(Dispatchers.IO) {
                val respBuf = ByteBuffer.allocate(4096)
                while (isActive && channel.isOpen) {
                    respBuf.clear()
                    val len = try {
                        channel.read(respBuf)
                    } catch (_: Exception) {
                        break
                    }
                    if (len <= 0) break
                    val respBytes = ByteArray(len)
                    System.arraycopy(respBuf.array(), 0, respBytes, 0, len)
                    val ipResp = PacketParser.buildIpv4UdpResponse(
                        srcIp = remoteIpCopy,
                        dstIp = clientIpCopy,
                        srcPort = packet.dstPort,
                        dstPort = packet.srcPort,
                        payload = respBytes,
                        payloadLen = len
                    )
                    pcapngWriter.offerPacket(ipResp, ipResp.size, appUid, appLabel, "ALLOW_RX", packet.domainOrSni)
                    writeToTun(ipResp)
                    udpSessions[key]?.lastActiveAt = System.currentTimeMillis()
                }
                closeUdpSession(key)
            }
            val created = UdpRelaySession(
                key = key,
                channel = channel,
                clientIp = clientIpCopy,
                clientPort = packet.srcPort,
                remoteIp = remoteIpCopy,
                remotePort = packet.dstPort,
                appUid = appUid,
                appLabel = appLabel,
                lastActiveAt = now,
                readerJob = readerJob
            )
            udpSessions[key] = created
            created
        } catch (_: Exception) {
            null
        }
    }

    private fun forwardTcpIpv4(packet: ParsedPacket, raw: ByteArray, appUid: Int, appLabel: String) {
        val key = "${packet.srcIp}:${packet.srcPort}->${packet.dstIp}:${packet.dstPort}"
        val now = System.currentTimeMillis()

        if (packet.isTcpRst) {
            closeTcpSession(key)
            return
        }

        if (packet.isTcpSyn) {
            closeTcpSession(key)
            serviceScope.launch(Dispatchers.IO) {
                openTcpSession(key, packet, appUid, appLabel, now)
            }
            return
        }

        val session = tcpSessions[key] ?: return
        session.lastActiveAt = now

        if (packet.payloadLength > 0) {
            try {
                val payloadBuf = ByteBuffer.wrap(raw, packet.payloadOffset, packet.payloadLength)
                while (payloadBuf.hasRemaining()) {
                    session.channel.write(payloadBuf)
                }
                session.clientNextSeq = (packet.tcpSeq + packet.payloadLength.toLong()) and 0xFFFFFFFFL
                val ackPkt = PacketParser.buildIpv4TcpPacket(
                    srcIp = session.remoteIp,
                    dstIp = session.clientIp,
                    srcPort = session.remotePort,
                    dstPort = session.clientPort,
                    seq = session.serverSeq,
                    ack = session.clientNextSeq,
                    flags = 0x10 // ACK
                )
                writeToTun(ackPkt)
            } catch (_: Exception) {
                sendTcpRst(session)
                closeTcpSession(key)
            }
        }

        if (packet.isTcpFin) {
            session.clientNextSeq = (packet.tcpSeq + packet.payloadLength.toLong() + 1L) and 0xFFFFFFFFL
            val finAck = PacketParser.buildIpv4TcpPacket(
                srcIp = session.remoteIp,
                dstIp = session.clientIp,
                srcPort = session.remotePort,
                dstPort = session.clientPort,
                seq = session.serverSeq,
                ack = session.clientNextSeq,
                flags = 0x11 // FIN + ACK
            )
            writeToTun(finAck)
            closeTcpSession(key)
        }
    }

    private fun openTcpSession(
        key: String,
        synPacket: ParsedPacket,
        appUid: Int,
        appLabel: String,
        now: Long
    ) {
        try {
            val channel = SocketChannel.open()
            if (!protect(channel.socket())) {
                channel.close()
                return
            }
            channel.socket().connect(
                InetSocketAddress(InetAddress.getByAddress(synPacket.dstIpBytes), synPacket.dstPort),
                4500
            )
            val initServerSeq = (System.nanoTime() and 0x7FFFFFFFL)
            val clientNext = (synPacket.tcpSeq + 1L) and 0xFFFFFFFFL
            val session = TcpRelaySession(
                key = key,
                channel = channel,
                clientIp = synPacket.srcIpBytes.copyOf(),
                clientPort = synPacket.srcPort,
                remoteIp = synPacket.dstIpBytes.copyOf(),
                remotePort = synPacket.dstPort,
                appUid = appUid,
                appLabel = appLabel,
                serverSeq = (initServerSeq + 1L) and 0xFFFFFFFFL,
                clientNextSeq = clientNext,
                lastActiveAt = now
            )
            tcpSessions[key] = session

            // Send SYN-ACK back to TUN
            val synAck = PacketParser.buildIpv4TcpPacket(
                srcIp = session.remoteIp,
                dstIp = session.clientIp,
                srcPort = session.remotePort,
                dstPort = session.clientPort,
                seq = initServerSeq,
                ack = clientNext,
                flags = 0x12 // SYN + ACK
            )
            writeToTun(synAck)

            session.readerJob = serviceScope.launch(Dispatchers.IO) {
                val readBuf = ByteBuffer.allocate(1380)
                while (isActive && channel.isOpen) {
                    readBuf.clear()
                    val n = try {
                        channel.read(readBuf)
                    } catch (_: Exception) {
                        -1
                    }
                    if (n < 0) {
                        val fin = PacketParser.buildIpv4TcpPacket(
                            srcIp = session.remoteIp,
                            dstIp = session.clientIp,
                            srcPort = session.remotePort,
                            dstPort = session.clientPort,
                            seq = session.serverSeq,
                            ack = session.clientNextSeq,
                            flags = 0x11
                        )
                        writeToTun(fin)
                        break
                    }
                    if (n == 0) continue
                    val chunk = ByteArray(n)
                    System.arraycopy(readBuf.array(), 0, chunk, 0, n)
                    val dataPkt = PacketParser.buildIpv4TcpPacket(
                        srcIp = session.remoteIp,
                        dstIp = session.clientIp,
                        srcPort = session.remotePort,
                        dstPort = session.clientPort,
                        seq = session.serverSeq,
                        ack = session.clientNextSeq,
                        flags = 0x18, // PSH + ACK
                        payload = chunk,
                        payloadLen = n
                    )
                    session.serverSeq = (session.serverSeq + n.toLong()) and 0xFFFFFFFFL
                    session.lastActiveAt = System.currentTimeMillis()
                    pcapngWriter.offerPacket(dataPkt, dataPkt.size, appUid, appLabel, "ALLOW_RX", null)
                    writeToTun(dataPkt)
                }
                closeTcpSession(key)
            }
        } catch (_: Exception) {
            val rst = PacketParser.buildIpv4TcpPacket(
                srcIp = synPacket.dstIpBytes,
                dstIp = synPacket.srcIpBytes,
                srcPort = synPacket.dstPort,
                dstPort = synPacket.srcPort,
                seq = 0L,
                ack = (synPacket.tcpSeq + 1L) and 0xFFFFFFFFL,
                flags = 0x14
            )
            writeToTun(rst)
        }
    }

    private fun sendTcpRst(session: TcpRelaySession) {
        val rst = PacketParser.buildIpv4TcpPacket(
            srcIp = session.remoteIp,
            dstIp = session.clientIp,
            srcPort = session.remotePort,
            dstPort = session.clientPort,
            seq = session.serverSeq,
            ack = session.clientNextSeq,
            flags = 0x14
        )
        writeToTun(rst)
    }

    private fun writeToTun(packetBytes: ByteArray) {
        synchronized(tunWriteLock) {
            runCatching {
                tunOutput?.write(packetBytes)
            }
        }
    }

    private fun startSessionCleanupLoop() {
        cleanupJob?.cancel()
        cleanupJob = serviceScope.launch(Dispatchers.IO) {
            while (isActive) {
                delay(15_000L)
                val now = System.currentTimeMillis()
                udpSessions.entries.forEach { (key, sess) ->
                    if (now - sess.lastActiveAt > 45_000L) closeUdpSession(key)
                }
                tcpSessions.entries.forEach { (key, sess) ->
                    if (now - sess.lastActiveAt > 90_000L) closeTcpSession(key)
                }
            }
        }
    }

    private fun closeUdpSession(key: String) {
        val sess = udpSessions.remove(key) ?: return
        runCatching { sess.channel.close() }
        sess.readerJob.cancel()
    }

    private fun closeTcpSession(key: String) {
        val sess = tcpSessions.remove(key) ?: return
        runCatching { sess.channel.close() }
        sess.readerJob?.cancel()
    }

    private suspend fun startPcapRecording() {
        if (pcapngWriter.isRecording()) return
        val dir = File(getExternalFilesDir("captures") ?: filesDir, "")
        dir.mkdirs()
        val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val file = File(dir, "adf_capture_$stamp.pcapng")
        val startedAt = System.currentTimeMillis()
        val sessionId = appContainer.repository.insertCaptureSession(
            CaptureSessionEntity(
                fileName = file.name,
                filePath = file.absolutePath,
                startedAt = startedAt
            )
        )
        pcapngWriter.start(file, sessionId, serviceScope) { stats ->
            appContainer.telemetryBus.updatePcapStats(stats)
            serviceScope.launch {
                runCatching {
                    appContainer.repository.updateCaptureStats(
                        id = sessionId,
                        endedAt = null,
                        packetCount = stats.packetsWritten,
                        byteCount = stats.bytesWritten,
                        droppedCount = stats.droppedFrames
                    )
                }
            }
        }
        appContainer.telemetryBus.updatePcapStats(pcapngWriter.snapshotStats())
        updateNotification("Firewall + IDS + PCAPNG Recording Active")
    }

    private suspend fun stopPcapRecording() {
        if (!pcapngWriter.isRecording()) return
        val sessionId = pcapngWriter.snapshotStats().sessionId
        val finalStats = pcapngWriter.stop()
        appContainer.telemetryBus.updatePcapStats(finalStats)
        if (sessionId != null) {
            runCatching {
                appContainer.repository.updateCaptureStats(
                    id = sessionId,
                    endedAt = System.currentTimeMillis(),
                    packetCount = finalStats.packetsWritten,
                    byteCount = finalStats.bytesWritten,
                    droppedCount = finalStats.droppedFrames
                )
            }
        }
        if (tunInterface != null) {
            updateNotification("Firewall & Inline IDS Active • TUN Armed")
        }
    }

    private fun stopVpnEngine() {
        packetLoopJob?.cancel()
        cleanupJob?.cancel()
        observerJob?.cancel()

        serviceScope.launch { stopPcapRecording() }

        udpSessions.keys.toList().forEach { closeUdpSession(it) }
        tcpSessions.keys.toList().forEach { closeTcpSession(it) }

        runCatching { tunOutput?.close() }
        tunOutput = null
        runCatching { tunInterface?.close() }
        tunInterface = null

        appContainer.telemetryBus.setVpnState(VpnEngineState.STOPPED)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Firewall & Packet Capture Shield",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Persistent status for Another Droid Firewall+ local VPN shield"
            }
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(statusText: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(statusText)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .build()
    }

    private fun updateNotification(statusText: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(statusText))
    }
}
