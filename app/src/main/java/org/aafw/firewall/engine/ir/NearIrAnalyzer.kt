package org.aafw.firewall.engine.ir

import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import kotlin.math.abs

data class IrHotspot(
    val normX: Float, // 0..1
    val normY: Float, // 0..1
    val intensityScore: Float, // 0..1
    val peakLuma: Int,
    val chromaSignature: String // NEAR_IR_VIOLET | SPECULAR_IR_CORE
)

data class IrAnalysisFrame(
    val timestamp: Long = System.currentTimeMillis(),
    val ambientLuma: Int = 0,
    val peakLuma: Int = 0,
    val hotspots: List<IrHotspot> = emptyList(),
    val frameWidth: Int = 0,
    val frameHeight: Int = 0
)

/**
 * Real-time CameraX YUV_420_888 near-IR (850nm–940nm) optical hotspot detector.
 * Smartphone CMOS sensors without strong IR-cut filters render near-IR emitters as high-luminance
 * specular white or violet/magenta-shifted point sources (elevated U and V chroma relative to neutral 128).
 */
class NearIrAnalyzer(
    private val getLumaThreshold: () -> Int,
    private val getChromaBiasThreshold: () -> Float,
    private val isFrozen: () -> Boolean,
    private val onResult: (IrAnalysisFrame) -> Unit
) : ImageAnalysis.Analyzer {

    companion object {
        private const val MAX_CANDIDATES = 96
    }

    private var lastProcessedMs = 0L
    // Reusable primitive scratch buffers (CameraX ImageAnalysis runs serially on one executor thread)
    private val candX = IntArray(MAX_CANDIDATES)
    private val candY = IntArray(MAX_CANDIDATES)
    private val candLuma = IntArray(MAX_CANDIDATES)
    private val candViolet = FloatArray(MAX_CANDIDATES)
    private val candIsViolet = BooleanArray(MAX_CANDIDATES)
    private val candUsed = BooleanArray(MAX_CANDIDATES)

    override fun analyze(image: ImageProxy) {
        try {
            val now = System.currentTimeMillis()
            if (isFrozen() || now - lastProcessedMs < 75L) return
            lastProcessedMs = now

            if (image.planes.size < 3) return
            val yPlane = image.planes[0]
            val uPlane = image.planes[1]
            val vPlane = image.planes[2]

            val width = image.width
            val height = image.height
            if (width <= 0 || height <= 0) return

            val yBuf = yPlane.buffer
            val uBuf = uPlane.buffer
            val vBuf = vPlane.buffer
            val yRowStride = yPlane.rowStride
            val yPixStride = yPlane.pixelStride
            val uRowStride = uPlane.rowStride
            val uPixStride = uPlane.pixelStride
            val vRowStride = vPlane.rowStride
            val vPixStride = vPlane.pixelStride

            val lumaThresh = getLumaThreshold().coerceIn(140, 254)
            val chromaBiasThresh = getChromaBiasThreshold().coerceIn(0.05f, 0.9f)

            val step = 6 // Subsample every 6px for real-time 15 FPS low-CPU scanning
            var totalLuma = 0L
            var sampleCount = 0
            var maxLuma = 0
            var candCount = 0

            var row = 0
            while (row < height) {
                val yRowOff = row * yRowStride
                val uvRow = row ushr 1
                val uRowOff = uvRow * uRowStride
                val vRowOff = uvRow * vRowStride

                var col = 0
                while (col < width) {
                    val yIdx = yRowOff + col * yPixStride
                    if (yIdx < yBuf.limit()) {
                        val luma = yBuf.get(yIdx).toInt() and 0xFF
                        totalLuma += luma
                        sampleCount++
                        if (luma > maxLuma) maxLuma = luma

                        if (luma >= lumaThresh && candCount < MAX_CANDIDATES) {
                            val uvCol = col ushr 1
                            val uIdx = uRowOff + uvCol * uPixStride
                            val vIdx = vRowOff + uvCol * vPixStride
                            val uVal = if (uIdx < uBuf.limit()) uBuf.get(uIdx).toInt() and 0xFF else 128
                            val vVal = if (vIdx < vBuf.limit()) vBuf.get(vIdx).toInt() and 0xFF else 128

                            // Near-IR signature on silicon CMOS: positive U (blue) + positive V (red) = violet/magenta shift
                            val uShift = ((uVal - 128) / 127f).coerceAtLeast(0f)
                            val vShift = ((vVal - 128) / 127f).coerceAtLeast(0f)
                            val violetScore = (uShift + vShift) * 0.5f
                            val isViolet = violetScore >= chromaBiasThresh * 0.45f
                            val isSpecularCore = luma >= 248 && abs(uVal - 128) <= 22 && abs(vVal - 128) <= 22

                            if (isViolet || isSpecularCore) {
                                candX[candCount] = col
                                candY[candCount] = row
                                candLuma[candCount] = luma
                                candViolet[candCount] = violetScore
                                candIsViolet[candCount] = isViolet
                                candUsed[candCount] = false
                                candCount++
                            }
                        }
                    }
                    col += step
                }
                row += step
            }

            val ambient = if (sampleCount > 0) (totalLuma / sampleCount).toInt() else 0

            // Cluster nearby candidate pixels into distinct IR point sources
            val hotspots = if (candCount == 0) {
                emptyList()
            } else {
                val list = ArrayList<IrHotspot>(8)
                val contrastGain = ((lumaThresh - ambient).coerceAtLeast(25)) / 255f
                val clusterRadiusSq = (minOf(width, height) * 0.08f).let { it * it }

                for (i in 0 until candCount) {
                    if (candUsed[i]) continue
                    val seedX = candX[i]
                    val seedY = candY[i]
                    candUsed[i] = true
                    var sumX = seedX.toFloat()
                    var sumY = seedY.toFloat()
                    var count = 1
                    var peakY = candLuma[i]
                    var bestViolet = candViolet[i]
                    var hasViolet = candIsViolet[i]

                    for (j in i + 1 until candCount) {
                        if (candUsed[j]) continue
                        val dx = (candX[j] - seedX).toFloat()
                        val dy = (candY[j] - seedY).toFloat()
                        if (dx * dx + dy * dy <= clusterRadiusSq) {
                            candUsed[j] = true
                            sumX += candX[j]
                            sumY += candY[j]
                            count++
                            if (candLuma[j] > peakY) peakY = candLuma[j]
                            if (candViolet[j] > bestViolet) bestViolet = candViolet[j]
                            if (candIsViolet[j]) hasViolet = true
                        }
                    }

                    // Point sources (IR LEDs / lasers) have concentrated high-contrast cores against darker surroundings
                    if (ambient < 190 || hasViolet) {
                        val normX = (sumX / count / width.toFloat()).coerceIn(0f, 1f)
                        val normY = (sumY / count / height.toFloat()).coerceIn(0f, 1f)
                        val score = ((peakY / 255f) * 0.55f + bestViolet * 0.3f + contrastGain * 0.15f)
                            .coerceIn(0.1f, 1f)
                        list.add(
                            IrHotspot(
                                normX = normX,
                                normY = normY,
                                intensityScore = score,
                                peakLuma = peakY,
                                chromaSignature = if (hasViolet) "NEAR_IR_VIOLET" else "SPECULAR_IR_CORE"
                            )
                        )
                    }
                }
                if (list.size > 1) list.sortByDescending { it.intensityScore }
                if (list.size > 6) list.subList(0, 6).toList() else list
            }

            onResult(
                IrAnalysisFrame(
                    timestamp = now,
                    ambientLuma = ambient,
                    peakLuma = maxLuma,
                    hotspots = hotspots,
                    frameWidth = width,
                    frameHeight = height
                )
            )
        } finally {
            image.close()
        }
    }
}
