package org.aafw.firewall

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.PixelFormat
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import org.aafw.firewall.engine.rf.RtlSdrUsbManager
import org.aafw.firewall.ui.MainAppShell
import org.aafw.firewall.ui.theme.AnotherDroidFirewallTheme
import org.aafw.firewall.ui.viewmodel.BluetoothViewModel
import org.aafw.firewall.ui.viewmodel.FirewallViewModel
import org.aafw.firewall.ui.viewmodel.IdsViewModel
import org.aafw.firewall.ui.viewmodel.IrViewModel
import org.aafw.firewall.ui.viewmodel.RfViewModel

class MainActivity : ComponentActivity() {

    private lateinit var viewModelFactory: ViewModelProvider.Factory
    private lateinit var firewallViewModel: FirewallViewModel
    private lateinit var idsViewModel: IdsViewModel
    private val bluetoothViewModelLazy = lazy(LazyThreadSafetyMode.NONE) {
        ViewModelProvider(this, viewModelFactory)[BluetoothViewModel::class.java]
    }
    private val rfViewModelLazy = lazy(LazyThreadSafetyMode.NONE) {
        ViewModelProvider(this, viewModelFactory)[RfViewModel::class.java]
    }
    private val irViewModelLazy = lazy(LazyThreadSafetyMode.NONE) {
        ViewModelProvider(this, viewModelFactory)[IrViewModel::class.java]
    }

    private val notificationPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> }

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (rfViewModelLazy.isInitialized()) {
                rfViewModelLazy.value.scanUsbDevices()
            }
            if (irViewModelLazy.isInitialized()) {
                irViewModelLazy.value.refreshUsbIrHardware()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFormat(PixelFormat.RGBA_8888)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            window.colorMode = ActivityInfo.COLOR_MODE_DEFAULT
        }
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT)
        )

        val container = (application as FirewallApplication).container
        viewModelFactory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T = when (modelClass) {
                FirewallViewModel::class.java -> FirewallViewModel(application, container) as T
                IdsViewModel::class.java -> IdsViewModel(application, container) as T
                BluetoothViewModel::class.java -> BluetoothViewModel(application, container) as T
                RfViewModel::class.java -> RfViewModel(application, container) as T
                IrViewModel::class.java -> IrViewModel(application, container) as T
                else -> throw IllegalArgumentException("Unknown ViewModel: ${modelClass.name}")
            }
        }

        firewallViewModel = ViewModelProvider(this, viewModelFactory)[FirewallViewModel::class.java]
        idsViewModel = ViewModelProvider(this, viewModelFactory)[IdsViewModel::class.java]

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        val usbFilter = IntentFilter().apply {
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
            addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
            addAction(RtlSdrUsbManager.ACTION_USB_PERMISSION)
        }
        ContextCompat.registerReceiver(
            this,
            usbReceiver,
            usbFilter,
            ContextCompat.RECEIVER_NOT_EXPORTED
        )

        setContent {
            AnotherDroidFirewallTheme {
                MainAppShell(
                    firewallViewModel = firewallViewModel,
                    idsViewModel = idsViewModel,
                    getBluetoothViewModel = { bluetoothViewModelLazy.value },
                    getRfViewModel = { rfViewModelLazy.value },
                    getIrViewModel = { irViewModelLazy.value }
                )
            }
        }
    }

    override fun onDestroy() {
        runCatching { unregisterReceiver(usbReceiver) }
        super.onDestroy()
    }
}
