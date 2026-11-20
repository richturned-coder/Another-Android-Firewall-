package com.example.engine.rf

import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.log10
import kotlin.math.sin
import kotlin.math.sqrt

data class DetectedRfPeak(
    val frequencyMhz: Double,
    val powerDb: Float,
    val snrDb: Float,
    val bandwidthKhz: Float,
    val estimatedModulation: String,
    val bandLabel: String,
    val protocolHint: String
)

data class SpectrumFrame(
    val timestamp: Long,
    val centerFreqMhz: Double,
    val sampleRateHz: Int,
    val binsDb: FloatArray, // FFT-shifted from -Fs/2 to +Fs/2
    val noiseFloorDb: Float,
    val peakPowerDb: Float,
    val peaks: List<DetectedRfPeak>,
    val ookPulseSummary: String?
)

/**
 * Pure-Kotlin zero-dependency in-place Radix-2 Cooley-Tukey FFT, noise-floor median estimator,
 * SNR peak detector, spectral modulation classifier, and OOK/ASK pulse-width burst analyzer.
 */
class Radix2FftEngine(val fftSize: Int = 1024) {
    private val real = DoubleArray(fftSize)
    private val imag = DoubleArray(fftSize)
    private val window = DoubleArray(fftSize) { i ->
        0.5 * (1.0 - cos(2.0 * PI * i / (fftSize - 1)))
    }
    private val magSq = DoubleArray(fftSize)

    fun processCu8Block(
        iqBytes: ByteArray,
        byteLength: Int,
        centerFreqMhz: Double,
        sampleRateHz: Int,
        peakThresholdDb: Float,
        bandLookup: (Double) -> Pair<String, String>
    ): SpectrumFrame {
        val samplePairs = minOf(fftSize, byteLength / 2)
        // Convert unsigned 8-bit I/Q (0..255 centered at 127.5) and compute DC removal
        var sumI = 0.0
        var sumQ = 0.0
        for (i in 0 until samplePairs) {
            sumI += (iqBytes[i * 2].toInt() and 0xFF) - 127.5
            sumQ += (iqBytes[i * 2 + 1].toInt() and 0xFF) - 127.5
        }
        val meanI = if (samplePairs > 0) sumI / samplePairs else 0.0
        val meanQ = if (samplePairs > 0) sumQ / samplePairs else 0.0

        var ampSum = 0.0
        var ampSqSum = 0.0
        var phaseDiffSqSum = 0.0
        var prevPhase = 0.0

        for (i in 0 until fftSize) {
            if (i < samplePairs) {
                val iVal = ((iqBytes[i * 2].toInt() and 0xFF) - 127.5 - meanI) / 127.5
                val qVal = ((iqBytes[i * 2 + 1].toInt() and 0xFF) - 127.5 - meanQ) / 127.5
                val env = sqrt(iVal * iVal + qVal * qVal)
                ampSum += env
                ampSqSum += env * env
                val phase = atan2(qVal, iVal)
                if (i > 0) {
                    var dp = phase - prevPhase
                    if (dp > PI) dp -= 2.0 * PI
                    if (dp < -PI) dp += 2.0 * PI
                    phaseDiffSqSum += dp * dp
                }
                prevPhase = phase
                real[i] = iVal * window[i]
                imag[i] = qVal * window[i]
            } else {
                real[i] = 0.0
                imag[i] = 0.0
            }
        }

        val ookSummary = detectOokBursts(iqBytes, byteLength, sampleRateHz)

        fftInPlace(real, imag)

        // FFT-shift into dBFS bins (-Fs/2 .. +Fs/2)
        val bins = FloatArray(fftSize)
        val half = fftSize / 2
        val norm = fftSize.toDouble() * 0.5
        for (i in 0 until fftSize) {
            val shiftedIdx = (i + half) % fftSize
            val r = real[i] / norm
            val im = imag[i] / norm
            val p = r * r + im * im
            magSq[shiftedIdx] = p
            val db = (10.0 * log10(p + 1e-12)).toFloat().coerceIn(-120f, 0f)
            bins[shiftedIdx] = db
        }

        val sortedBins = bins.copyOf().apply { sort() }
        val noiseFloor = sortedBins[fftSize / 2]
        val peakPower = sortedBins.last()

        val ampMean = if (samplePairs > 0) ampSum / samplePairs else 0.0
        val ampVar = if (samplePairs > 0) (ampSqSum / samplePairs) - ampMean * ampMean else 0.0
        val phaseVar = if (samplePairs > 1) phaseDiffSqSum / (samplePairs - 1) else 0.0

        val binWidthHz = sampleRateHz.toDouble() / fftSize.toDouble()
        val peaks = detectPeaks(
            bins = bins,
            noiseFloor = noiseFloor,
            thresholdDb = peakThresholdDb,
            centerFreqMhz = centerFreqMhz,
            sampleRateHz = sampleRateHz,
            binWidthHz = binWidthHz,
            ampVar = ampVar,
            phaseVar = phaseVar,
            bandLookup = bandLookup
        )

        return SpectrumFrame(
            timestamp = System.currentTimeMillis(),
            centerFreqMhz = centerFreqMhz,
            sampleRateHz = sampleRateHz,
            binsDb = bins,
            noiseFloorDb = noiseFloor,
            peakPowerDb = peakPower,
            peaks = peaks,
            ookPulseSummary = ookSummary
        )
    }

    private fun detectPeaks(
        bins: FloatArray,
        noiseFloor: Float,
        thresholdDb: Float,
        centerFreqMhz: Double,
        sampleRateHz: Int,
        binWidthHz: Double,
        ampVar: Double,
        phaseVar: Double,
        bandLookup: (Double) -> Pair<String, String>
    ): List<DetectedRfPeak> {
        val found = ArrayList<DetectedRfPeak>()
        val half = bins.size / 2
        var i = 2
        while (i < bins.size - 2) {
            // Skip tiny DC spike around center bin
            if (abs(i - half) <= 2) {
                i++
                continue
            }
            val v = bins[i]
            val snr = v - noiseFloor
            if (snr >= thresholdDb && v >= bins[i - 1] && v >= bins[i + 1]) {
                // Measure -6 dB bandwidth around peak
                var left = i
                while (left > 0 && bins[left] > v - 6f) left--
                var right = i
                while (right < bins.size - 1 && bins[right] > v - 6f) right++
                val bwKhz = ((right - left + 1) * binWidthHz / 1000.0).toFloat()
                val offsetHz = (i - half) * binWidthHz
                val freqMhz = centerFreqMhz + (offsetHz / 1_000_000.0)
                val mod = classifyModulation(bwKhz, ampVar, phaseVar)
                val (bandName, protoHint) = bandLookup(freqMhz)
                found.add(
                    DetectedRfPeak(
                        frequencyMhz = freqMhz,
                        powerDb = v,
                        snrDb = snr,
                        bandwidthKhz = bwKhz,
                        estimatedModulation = mod,
                        bandLabel = bandName,
                        protocolHint = protoHint
                    )
                )
                i = right + 2
            } else {
                i++
            }
        }
        return found.sortedByDescending { it.snrDb }.take(8)
    }

    private fun classifyModulation(bwKhz: Float, ampVar: Double, phaseVar: Double): String = when {
        bwKhz > 400f -> "Broadband / OFDM / Spread"
        bwKhz in 110f..400f -> "WFM (Wideband FM)"
        ampVar > 0.045 && bwKhz < 80f -> "OOK / ASK (ISM Pulse)"
        phaseVar > 0.35 && bwKhz < 110f -> "FSK / GFSK / Telemetry"
        else -> "NFM / Narrowband Carrier"
    }

    private fun detectOokBursts(iqBytes: ByteArray, byteLength: Int, sampleRateHz: Int): String? {
        val pairs = minOf(byteLength / 2, 8192)
        if (pairs < 256) return null
        val env = DoubleArray(pairs)
        var maxEnv = 0.0
        var sumEnv = 0.0
        for (i in 0 until pairs) {
            val ii = ((iqBytes[i * 2].toInt() and 0xFF) - 127.5) / 127.5
            val qq = ((iqBytes[i * 2 + 1].toInt() and 0xFF) - 127.5) / 127.5
            val e = sqrt(ii * ii + qq * qq)
            env[i] = e
            if (e > maxEnv) maxEnv = e
            sumEnv += e
        }
        val avgEnv = sumEnv / pairs
        if (maxEnv < avgEnv * 2.2 || maxEnv < 0.12) return null

        val thresh = avgEnv + (maxEnv - avgEnv) * 0.45
        var inPulse = false
        var pulseStart = 0
        val pulseWidthsUs = ArrayList<Int>()
        for (i in 0 until pairs) {
            if (!inPulse && env[i] >= thresh) {
                inPulse = true
                pulseStart = i
            } else if (inPulse && env[i] < thresh * 0.85) {
                inPulse = false
                val widthSamples = i - pulseStart
                val widthUs = ((widthSamples * 1_000_000.0) / sampleRateHz).toInt()
                if (widthUs in 40..15_000) {
                    pulseWidthsUs.add(widthUs)
                }
            }
        }
        if (pulseWidthsUs.size < 4) return null
        val shortUs = pulseWidthsUs.minOrNull() ?: 0
        val longUs = pulseWidthsUs.maxOrNull() ?: 0
        return "OOK/ASK Burst: ${pulseWidthsUs.size} pulses detected (min=${shortUs}us, max=${longUs}us)"
    }

    private fun fftInPlace(re: DoubleArray, im: DoubleArray) {
        val n = re.size
        var j = 0
        for (i in 1 until n) {
            var bit = n shr 1
            while ((j and bit) != 0) {
                j = j xor bit
                bit = bit shr 1
            }
            j = j xor bit
            if (i < j) {
                val tr = re[i]; re[i] = re[j]; re[j] = tr
                val ti = im[i]; im[i] = im[j]; im[j] = ti
            }
        }
        var len = 2
        while (len <= n) {
            val ang = -2.0 * PI / len
            val wlenRe = cos(ang)
            val wlenIm = sin(ang)
            var i = 0
            while (i < n) {
                var wRe = 1.0
                var wIm = 0.0
                val half = len shr 1
                for (k in 0 until half) {
                    val uRe = re[i + k]
                    val uIm = im[i + k]
                    val vRe = re[i + k + half] * wRe - im[i + k + half] * wIm
                    val vIm = re[i + k + half] * wIm + im[i + k + half] * wRe
                    re[i + k] = uRe + vRe
                    im[i + k] = uIm + vIm
                    re[i + k + half] = uRe - vRe
                    im[i + k + half] = uIm - vIm
                    val nextRe = wRe * wlenRe - wIm * wlenIm
                    wIm = wRe * wlenIm + wIm * wlenRe
                    wRe = nextRe
                }
                i += len
            }
            len = len shl 1
        }
    }
}
