package org.aafw.firewall.engine.rf

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.net.Uri
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import org.aafw.firewall.BuildConfig
import java.io.BufferedInputStream

data class DetectedUsbHardware(
    val deviceName: String,
    val vendorId: Int,
    val productId: Int,
    val modelLabel: String,
    val isSupportedSdr: Boolean,
    val isIrSerialBridge: Boolean,
    val hasPermission: Boolean,
    val usbDevice: UsbDevice
)

class RtlSdrUsbManager(private val context: Context) {
    companion object {
        const val ACTION_USB_PERMISSION = "${BuildConfig.APPLICATION_ID}.USB_SDR_PERMISSION"

        private val sdrCatalog = mapOf(
            (0x0BDA to 0x2838) to "RTL-SDR (RTL2832U / R820T2)",
            (0x0BDA to 0x2832) to "RTL-SDR (RTL2832U Generic)",
            (0x1D50 to 0x6089) to "HackRF One (1 MHz – 6 GHz)",
            (0x1D50 to 0x60A1) to "Airspy / Airspy Mini"
        )

        private val irBridgeCatalog = mapOf(
            (0x0403 to 0x6001) to "FTDI USB-C Serial / IR Bridge",
            (0x10C4 to 0xEA60) to "CP210x USB-C IR Transceiver",
            (0x1A86 to 0x7523) to "CH340 USB-C IR Photodiode Bridge"
        )
    }

    private val usbManager: UsbManager? by lazy {
        context.getSystemService(Context.USB_SERVICE) as? UsbManager
    }

    fun enumerateDevices(): List<DetectedUsbHardware> {
        val mgr = usbManager ?: return emptyList()
        return mgr.deviceList.values.map { dev ->
            val key = dev.vendorId to dev.productId
            val sdrLabel = sdrCatalog[key]
            val irLabel = irBridgeCatalog[key]
            DetectedUsbHardware(
                deviceName = dev.deviceName,
                vendorId = dev.vendorId,
                productId = dev.productId,
                modelLabel = sdrLabel ?: irLabel ?: (dev.productName ?: "USB Device ${"%04X:%04X".format(dev.vendorId, dev.productId)}"),
                isSupportedSdr = sdrLabel != null,
                isIrSerialBridge = irLabel != null,
                hasPermission = mgr.hasPermission(dev),
                usbDevice = dev
            )
        }
    }

    fun requestUsbPermission(device: UsbDevice) {
        val mgr = usbManager ?: return
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            PendingIntent.FLAG_MUTABLE
        } else {
            0
        }
        val permissionIntent = Intent(ACTION_USB_PERMISSION).setPackage(context.packageName)
        val pi = PendingIntent.getBroadcast(context, 0, permissionIntent, flags)
        mgr.requestPermission(device, pi)
    }

    /**
     * Opens an attached RTL2832U USB-OTG dongle, initializes basic USB bulk endpoint streaming,
     * and yields raw 8-bit unsigned I/Q buffers to the caller until cancelled.
     */
    suspend fun streamRtlSdrBulk(
        device: UsbDevice,
        sampleRateHz: Int,
        onStatus: (String) -> Unit,
        onIqBlock: (ByteArray, Int) -> Unit
    ) = withContext(Dispatchers.IO) {
        val mgr = usbManager
        if (mgr == null || !mgr.hasPermission(device)) {
            onStatus("USB permission required before opening ${device.deviceName}.")
            return@withContext
        }

        var conn: UsbDeviceConnection? = null
        var claimedInterface: UsbInterface? = null
        try {
            conn = mgr.openDevice(device)
            if (conn == null) {
                onStatus("Failed to open UsbDeviceConnection for ${device.deviceName}.")
                return@withContext
            }

            var bulkIn: UsbEndpoint? = null
            for (ifaceIdx in 0 until device.interfaceCount) {
                val iface = device.getInterface(ifaceIdx)
                for (epIdx in 0 until iface.endpointCount) {
                    val ep = iface.getEndpoint(epIdx)
                    if (ep.type == UsbConstants.USB_ENDPOINT_XFER_BULK && ep.direction == UsbConstants.USB_DIR_IN) {
                        claimedInterface = iface
                        bulkIn = ep
                        break
                    }
                }
                if (bulkIn != null) break
            }

            if (claimedInterface == null || bulkIn == null) {
                onStatus("No USB bulk-IN I/Q endpoint found on ${device.deviceName}.")
                return@withContext
            }

            if (!conn.claimInterface(claimedInterface, true)) {
                onStatus("Could not claim USB interface on ${device.deviceName}.")
                return@withContext
            }

            // Initialize RTL2832U baseband FIFO reset & sample rate via vendor control transfers
            if (device.vendorId == 0x0BDA) {
                initRtl2832uControlTransfers(conn, sampleRateHz)
            }
            onStatus("Streaming raw USB-OTG I/Q bulk transfers from ${device.deviceName}...")

            val buffer = ByteArray(16_384)
            while (isActive) {
                val read = conn.bulkTransfer(bulkIn, buffer, buffer.size, 500)
                if (read > 0) {
                    onIqBlock(buffer, read)
                } else {
                    delay(15L)
                }
            }
        } catch (e: Exception) {
            onStatus("USB SDR stream error: ${e.message ?: e.javaClass.simpleName}")
        } finally {
            if (conn != null && claimedInterface != null) {
                runCatching { conn.releaseInterface(claimedInterface) }
            }
            runCatching { conn?.close() }
        }
    }

    /**
     * Streams a real offline RTL-SDR `.cu8` / `.iq` file (unsigned 8-bit interleaved I/Q)
     * through the exact same FFT/waterfall/peak pipeline.
     */
    suspend fun streamCu8File(
        uri: Uri,
        onStatus: (String) -> Unit,
        onIqBlock: (ByteArray, Int) -> Unit
    ) = withContext(Dispatchers.IO) {
        try {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                val bis = BufferedInputStream(stream, 32_768)
                val chunk = ByteArray(16_384)
                onStatus("Analyzing offline .cu8 I/Q capture stream...")
                while (isActive) {
                    val read = bis.read(chunk)
                    if (read <= 0) break
                    onIqBlock(chunk, read)
                    delay(65L) // ~15 FPS waterfall playback
                }
                onStatus("Finished analyzing .cu8 I/Q capture file.")
            } ?: onStatus("Unable to open selected .cu8 file.")
        } catch (e: Exception) {
            onStatus("Error reading .cu8 file: ${e.message ?: e.javaClass.simpleName}")
        }
    }

    private fun initRtl2832uControlTransfers(conn: UsbDeviceConnection, sampleRateHz: Int) {
        // Basic RTL2832U SYS/USB block enable & FIFO reset vendor writes (requestType 0x40)
        fun writeReg(block: Int, addr: Int, value: Int, len: Int = 1) {
            val data = if (len == 1) byteArrayOf((value and 0xFF).toByte())
            else byteArrayOf(((value ushr 8) and 0xFF).toByte(), (value and 0xFF).toByte())
            val index = (block shl 8) or 0x10
            conn.controlTransfer(0x40, 0, addr, index, data, data.size, 300)
        }
        writeReg(block = 1, addr = 0x2000, value = 0x09) // USB_SYSCTL
        writeReg(block = 1, addr = 0x2140, value = 0x09) // USB_EPA_CTL reset
        writeReg(block = 1, addr = 0x2140, value = 0x00) // USB_EPA_CTL active
        // Sample rate ratio (28.8 MHz crystal)
        val ratio = ((28_800_000L * (1L shl 22)) / sampleRateHz.coerceIn(225_001, 3_200_000)) and 0x0FFFFFFCL
        writeReg(block = 0, addr = 0x019F, value = ((ratio ushr 16) and 0xFFFF).toInt(), len = 2)
        writeReg(block = 0, addr = 0x01A1, value = (ratio and 0xFFFF).toInt(), len = 2)
    }
}
