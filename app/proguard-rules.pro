# Another Droid Firewall+ (org.aafw.firewall) R8 / ProGuard Rules

# Preserve line numbers for crash triage without leaking developer source file paths
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Keep Android entry points registered in AndroidManifest.xml
-keep class org.aafw.firewall.FirewallApplication { *; }
-keep class org.aafw.firewall.MainActivity { *; }
-keep class org.aafw.firewall.vpn.FirewallVpnService { *; }

# Keep Room database, generated _Impl classes, DAOs, and entity constructors/fields
-keep class org.aafw.firewall.data.local.FirewallDatabase { *; }
-keep class * extends org.aafw.firewall.data.local.FirewallDatabase { *; }
-keep class org.aafw.firewall.data.local.*Dao* { *; }
-keep class org.aafw.firewall.data.local.*Entity { *; }
-keep enum org.aafw.firewall.data.local.* { *; }

# Keep ViewModels instantiated via ViewModelProvider.Factory
-keep class org.aafw.firewall.ui.viewmodel.*ViewModel {
    public <init>(...);
}

# Keep USB-OTG & Bluetooth/RF data models and reflection-safe enums
-keep enum org.aafw.firewall.engine.** { *; }
-keep enum org.aafw.firewall.vpn.** { *; }
