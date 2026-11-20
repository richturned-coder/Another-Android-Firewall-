package org.aafw.firewall.engine.network

import android.content.pm.ApplicationInfo
import android.content.pm.ResolveInfo
import java.util.Locale

/**
 * Resolves human-readable application labels without invoking PackageManager.getApplicationLabel()
 * or PackageManager.getResourcesForApplication().
 *
 * Avoids mapping foreign APKs, RRO overlays, and shared libraries (e.g. TrichromeLibrary) into
 * this process's native AssetManager/ApkAssets tables—eliminating ApkAssets weak-reference GC
 * warnings, native memory churn, and unnecessary parsing of untrusted APK resource tables.
 */
object AppLabelResolver {

    private val knownPackages = mapOf(
        "com.android.chrome" to "Chrome",
        "com.android.camera2" to "Camera",
        "com.google.android.GoogleCamera" to "Camera",
        "com.android.settings" to "Settings",
        "com.android.vending" to "Play Store",
        "com.android.dialer" to "Phone",
        "com.google.android.dialer" to "Phone",
        "com.android.contacts" to "Contacts",
        "com.google.android.contacts" to "Contacts",
        "com.android.deskclock" to "Clock",
        "com.google.android.deskclock" to "Clock",
        "com.android.calendar" to "Calendar",
        "com.google.android.calendar" to "Calendar",
        "com.android.mms" to "Messages",
        "com.google.android.apps.messaging" to "Messages",
        "com.google.android.gm" to "Gmail",
        "com.google.android.youtube" to "YouTube",
        "com.google.android.apps.youtube.music" to "YouTube Music",
        "com.google.android.apps.maps" to "Maps",
        "com.google.android.apps.docs" to "Drive",
        "com.google.android.apps.photos" to "Photos",
        "com.google.android.apps.safetyhub" to "Personal Safety",
        "com.google.android.apps.tachyon" to "Meet",
        "com.google.android.apps.nbu.files" to "Files",
        "com.google.android.documentsui" to "Files",
        "com.android.documentsui" to "Files",
        "com.android.stk" to "SIM Toolkit",
        "com.google.android.googlequicksearchbox" to "Google",
        "com.google.android.gms" to "Google Play Services",
        "com.android.shell" to "ADB Shell"
    )

    private val genericSegments = setOf(
        "com", "org", "net", "io", "dev", "app", "apps", "android", "google",
        "mobile", "client", "main", "release", "beta", "lite", "pro", "free"
    )

    fun resolve(resolveInfo: ResolveInfo?, appInfo: ApplicationInfo?): String {
        val direct = resolveInfo?.nonLocalizedLabel?.toString()?.trim()?.takeIf { it.isNotEmpty() }
            ?: resolveInfo?.activityInfo?.nonLocalizedLabel?.toString()?.trim()?.takeIf { it.isNotEmpty() }
            ?: appInfo?.nonLocalizedLabel?.toString()?.trim()?.takeIf { it.isNotEmpty() }
        if (direct != null) return direct

        val pkg = appInfo?.packageName
            ?: resolveInfo?.activityInfo?.packageName
            ?: return "Unknown App"

        return resolveFromPackageName(pkg)
    }

    fun resolveFromPackageName(packageName: String): String {
        knownPackages[packageName]?.let { return it }

        val segments = packageName.split('.').filter { it.isNotBlank() }
        if (segments.isEmpty()) return packageName

        val candidate = segments.asReversed().firstOrNull { seg ->
            seg.lowercase(Locale.US) !in genericSegments
        } ?: segments.last()

        return humanizeToken(candidate).ifBlank { packageName }
    }

    private fun humanizeToken(raw: String): String {
        val spaced = buildString(raw.length + 8) {
            for (i in raw.indices) {
                val ch = raw[i]
                when {
                    ch == '_' || ch == '-' -> append(' ')
                    i > 0 && ch.isUpperCase() && raw[i - 1].isLowerCase() -> {
                        append(' ')
                        append(ch)
                    }
                    else -> append(ch)
                }
            }
        }
        return spaced
            .split(' ')
            .filter { it.isNotBlank() }
            .joinToString(" ") { word ->
                if (word.length <= 3 && word.all { it.isUpperCase() || it.isDigit() }) {
                    word
                } else {
                    word.replaceFirstChar { c ->
                        if (c.isLowerCase()) c.titlecase(Locale.US) else c.toString()
                    }
                }
            }
    }
}
