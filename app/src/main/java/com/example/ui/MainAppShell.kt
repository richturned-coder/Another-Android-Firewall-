package com.example.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.NavigationRailItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.example.R
import com.example.ui.screens.BluetoothScreen
import com.example.ui.screens.FirewallScreen
import com.example.ui.screens.IdsScreen
import com.example.ui.screens.IrSpotterScreen
import com.example.ui.screens.RfSpectrumScreen
import com.example.ui.viewmodel.BluetoothViewModel
import com.example.ui.viewmodel.FirewallViewModel
import com.example.ui.viewmodel.IdsViewModel
import com.example.ui.viewmodel.IrViewModel
import com.example.ui.viewmodel.RfViewModel
import kotlinx.coroutines.launch

const val ROUTE_FIREWALL = "firewall"
const val ROUTE_IDS = "ids"
const val ROUTE_BLUETOOTH = "bluetooth"
const val ROUTE_RF = "rf"
const val ROUTE_IR = "ir"

private data class NavDestination(
    val route: String,
    val labelRes: Int,
    val icon: ImageVector,
    val testTag: String
)

private val topDestinations = listOf(
    NavDestination(ROUTE_FIREWALL, R.string.nav_firewall, Icons.Default.Shield, "nav_firewall"),
    NavDestination(ROUTE_IDS, R.string.nav_ids, Icons.Default.GppMaybe, "nav_ids"),
    NavDestination(ROUTE_BLUETOOTH, R.string.nav_bluetooth, Icons.Default.Bluetooth, "nav_bluetooth"),
    NavDestination(ROUTE_RF, R.string.nav_rf, Icons.Default.Radar, "nav_rf"),
    NavDestination(ROUTE_IR, R.string.nav_ir, Icons.Default.Visibility, "nav_ir")
)

@Composable
fun MainAppShell(
    firewallViewModel: FirewallViewModel,
    idsViewModel: IdsViewModel,
    getBluetoothViewModel: () -> BluetoothViewModel,
    getRfViewModel: () -> RfViewModel,
    getIrViewModel: () -> IrViewModel
) {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route ?: ROUTE_FIREWALL
    val idsAlerts by idsViewModel.alerts.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val coroutineScope = rememberCoroutineScope()

    fun showMessage(msg: String) {
        coroutineScope.launch {
            snackbarHostState.showSnackbar(msg)
        }
    }

    fun navigateTo(route: String) {
        navController.navigate(route) {
            popUpTo(navController.graph.findStartDestination().id) {
                saveState = true
            }
            launchSingleTop = true
            restoreState = true
        }
    }

    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val useRail = maxWidth >= 680.dp

        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            contentWindowInsets = WindowInsets.safeDrawing,
            snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
            bottomBar = {
                if (!useRail) {
                    NavigationBar(
                        containerColor = MaterialTheme.colorScheme.surface,
                        windowInsets = WindowInsets.navigationBars
                    ) {
                        topDestinations.forEach { dest ->
                            val selected = currentRoute == dest.route
                            NavigationBarItem(
                                selected = selected,
                                onClick = { navigateTo(dest.route) },
                                modifier = Modifier.testTag(dest.testTag),
                                icon = {
                                    if (dest.route == ROUTE_IDS && idsAlerts.isNotEmpty()) {
                                        BadgedBox(
                                            badge = {
                                                Badge(
                                                    containerColor = MaterialTheme.colorScheme.error,
                                                    contentColor = MaterialTheme.colorScheme.onError
                                                ) {
                                                    Text(idsAlerts.size.coerceAtMost(99).toString())
                                                }
                                            }
                                        ) {
                                            Icon(dest.icon, contentDescription = stringResource(dest.labelRes))
                                        }
                                    } else {
                                        Icon(dest.icon, contentDescription = stringResource(dest.labelRes))
                                    }
                                },
                                label = { Text(stringResource(dest.labelRes), maxLines = 1) },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = MaterialTheme.colorScheme.primary,
                                    selectedTextColor = MaterialTheme.colorScheme.primary,
                                    indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                                    unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                    unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            )
                        }
                    }
                }
            }
        ) { innerPadding ->
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                if (useRail) {
                    NavigationRail(
                        containerColor = MaterialTheme.colorScheme.surface,
                        modifier = Modifier.fillMaxHeight()
                    ) {
                        topDestinations.forEach { dest ->
                            val selected = currentRoute == dest.route
                            NavigationRailItem(
                                selected = selected,
                                onClick = { navigateTo(dest.route) },
                                modifier = Modifier.testTag(dest.testTag),
                                icon = {
                                    Icon(dest.icon, contentDescription = stringResource(dest.labelRes))
                                },
                                label = { Text(stringResource(dest.labelRes)) },
                                colors = NavigationRailItemDefaults.colors(
                                    selectedIconColor = MaterialTheme.colorScheme.primary,
                                    selectedTextColor = MaterialTheme.colorScheme.primary,
                                    indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                                    unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                    unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            )
                        }
                    }
                }

                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxHeight(),
                    contentAlignment = Alignment.TopCenter
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxHeight()
                            .widthIn(max = 840.dp)
                    ) {
                        NavHost(
                            navController = navController,
                            startDestination = ROUTE_FIREWALL
                        ) {
                            composable(ROUTE_FIREWALL) {
                                FirewallScreen(
                                    viewModel = firewallViewModel,
                                    onShowMessage = ::showMessage
                                )
                            }
                            composable(ROUTE_IDS) {
                                IdsScreen(
                                    viewModel = idsViewModel,
                                    onShowMessage = ::showMessage
                                )
                            }
                            composable(ROUTE_BLUETOOTH) {
                                val bluetoothViewModel = remember { getBluetoothViewModel() }
                                BluetoothScreen(
                                    viewModel = bluetoothViewModel,
                                    onShowMessage = ::showMessage
                                )
                            }
                            composable(ROUTE_RF) {
                                val rfViewModel = remember { getRfViewModel() }
                                RfSpectrumScreen(
                                    viewModel = rfViewModel
                                )
                            }
                            composable(ROUTE_IR) {
                                val irViewModel = remember { getIrViewModel() }
                                IrSpotterScreen(
                                    viewModel = irViewModel,
                                    onShowMessage = ::showMessage
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
