package com.example.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp

private val TacticalAmoledColorScheme = darkColorScheme(
    primary = PhosphorCyan,
    onPrimary = OnCyan,
    primaryContainer = CyanContainer,
    onPrimaryContainer = PhosphorCyan,
    secondary = TacticalAmber,
    onSecondary = OnAmber,
    secondaryContainer = AmberContainer,
    onSecondaryContainer = TacticalAmber,
    tertiary = SignalEmerald,
    onTertiary = OnEmerald,
    tertiaryContainer = EmeraldContainer,
    onTertiaryContainer = SignalEmerald,
    error = AlertCrimson,
    onError = OnCrimson,
    errorContainer = CrimsonContainer,
    onErrorContainer = AlertCrimson,
    background = ObsidianBlack,
    onBackground = TextPrimary,
    surface = ConsoleSurface,
    onSurface = TextPrimary,
    surfaceVariant = PanelMid,
    onSurfaceVariant = TextSecondary,
    surfaceContainerLowest = ObsidianBlack,
    surfaceContainerLow = PanelLow,
    surfaceContainer = PanelMid,
    surfaceContainerHigh = PanelHigh,
    surfaceContainerHighest = PanelHighest,
    outline = HairlineStrong,
    outlineVariant = HairlineBorder
)

val TacticalShapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(6.dp),
    medium = RoundedCornerShape(10.dp),
    large = RoundedCornerShape(14.dp),
    extraLarge = RoundedCornerShape(20.dp)
)

@Composable
fun AnotherDroidFirewallTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = TacticalAmoledColorScheme,
        typography = AppTypography,
        shapes = TacticalShapes,
        content = content
    )
}
