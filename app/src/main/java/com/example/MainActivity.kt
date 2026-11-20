package com.example

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Color
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
import com.example.engine.rf.RtlSdrUsbManager
import com.example.ui.MainAppShell
import com.example.ui.theme.AnotherDroidFirewallTheme
import com.example.ui.viewmodel.BluetoothViewModel
import com.example.ui.viewmodel.FirewallViewModel
import com.example.ui.viewmodel.IdsViewModel
import com.example.ui.viewmodel.IrViewModel
import com.example.ui.viewmodel.RfViewModel

class MainActivity : ComponentActivity() {

    private lateinit var firewallViewModel: FirewallViewModel
    private lateinit var idsViewModel: IdsViewModel
    private lateinit var bluetoothViewModel: BluetoothViewModel
    private lateinit var rfViewModel: RfViewModel
    private lateinit var irViewModel: IrViewModel

    private val notificationPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> }

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            rfViewModel.scanUsbDevices()
            irViewModel.refreshUsbIrHardware()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT)
        )

        val container = (application as FirewallApplication).container
        val factory = object : ViewModelProvider.Factory {
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

        firewallViewModel = ViewModelProvider(this, factory)[FirewallViewModel::class.java]
        idsViewModel = ViewModelProvider(this, factory)[IdsViewModel::class.java]
        bluetoothViewModel = ViewModelProvider(this, factory)[BluetoothViewModel::class.java]
        rfViewModel = ViewModelProvider(this, factory)[RfViewModel::class.java]
        irViewModel = ViewModelProvider(this, factory)[IrViewModel::class.java]

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
                    bluetoothViewModel = bluetoothViewModel,
                    rfViewModel = rfViewModel,
                    irViewModel = irViewModel
                )
            }
        }
    }

    override fun onDestroy() {
        runCatching { unregisterReceiver(usbReceiver) }
        super.onDestroy()
    }
}
