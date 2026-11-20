package org.aafw.firewall

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import org.aafw.firewall.engine.bluetooth.BleAdParser
import org.aafw.firewall.engine.bluetooth.BtSnoopParser
import org.aafw.firewall.engine.network.IdsEngine
import org.aafw.firewall.engine.network.PacketParser
import org.aafw.firewall.engine.rf.Radix2FftEngine
import java.io.ByteArrayInputStream

/**
 * Tier 2: Coverage-guided JVM fuzz targets powered by Jazzer (libFuzzer).
 *
 * - Default `gradle :app:testDebugUnitTest` executes in fast regression mode (replaying corpus seeds).
 * - Deep fuzzing mode (CI / local): `JAZZER_FUZZ=1 gradle :app:testDebugUnitTest --tests "*.SecurityParsersFuzzTest"`
 */
class SecurityParsersFuzzTest {

    private val idsEngine = IdsEngine()
    private val fftEngine = Radix2FftEngine(fftSize = 256)

    @FuzzTest(maxDuration = "5m")
    fun fuzzPacketAndIdsPipeline(data: FuzzedDataProvider) {
        val raw = data.consumeRemainingAsBytes()
        val parsed = PacketParser.parse(raw) ?: return
        idsEngine.inspect(parsed, appUid = 10099, appLabel = "JazzerFuzz")
    }

    @FuzzTest(maxDuration = "5m")
    fun fuzzBtSnoopParser(data: FuzzedDataProvider) {
        // 50% of runs prepend a valid 16-byte RFC 1761 BTSnoop v1 header so the fuzzer
        // immediately explores deep HCI/L2CAP/ATT/BLE-AD decoding paths.
        val body = if (data.consumeBoolean()) {
            VALID_BTSNOOP_HEADER + data.consumeRemainingAsBytes()
        } else {
            data.consumeRemainingAsBytes()
        }
        BtSnoopParser.parse(ByteArrayInputStream(body), "jazzer-btsnoop")
    }

    @FuzzTest(maxDuration = "5m")
    fun fuzzBleAdTlvParser(data: FuzzedDataProvider) {
        BleAdParser.parseAdStructures(data.consumeRemainingAsBytes())
    }

    @FuzzTest(maxDuration = "5m")
    fun fuzzRadix2FftEngine(data: FuzzedDataProvider) {
        val sampleRate = data.consumeInt()
        val byteLen = data.consumeInt()
        val centerFreq = data.consumeDouble()
        val threshold = data.consumeFloat()
        val iqBytes = data.consumeRemainingAsBytes()
        fftEngine.processCu8Block(
            iqBytes = iqBytes,
            byteLength = byteLen,
            centerFreqMhz = centerFreq,
            sampleRateHz = sampleRate,
            peakThresholdDb = threshold
        ) { "FuzzBand" to "FuzzProto" }
    }

    companion object {
        // "btsnoop\0" + version=1 + datalink=1002 (HCI UART H4)
        private val VALID_BTSNOOP_HEADER = byteArrayOf(
            0x62, 0x74, 0x73, 0x6E, 0x6F, 0x6F, 0x70, 0x00,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x03, 0xEA.toByte()
        )
    }
}
