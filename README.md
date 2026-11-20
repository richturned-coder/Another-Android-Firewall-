# Another Android Firewall+

**Another Android Firewall+** is a multi-domain, on-device Android security and tactical telemetry application built with Kotlin and Jetpack Compose. Designed for security researchers, defenders, and privacy-focused users, it combines a local VPN-based packet firewall and Intrusion Detection System (IDS) with Bluetooth, Near-Infrared (IR), and Software-Defined Radio (RF) monitoring in a single hardened interface.

## Core Capabilities

- **Local VPN Firewall & Traffic Attribution**
  - On-device packet interception and filtering via `FirewallVpnService` and `FirewallRuleEngine`—no root required.
  - Real-time packet dissection (`PacketParser`), live telemetry streaming (`VpnTelemetryBus`), and human-readable app attribution (`AppLabelResolver`).
  - Native **PCAPNG** export (`PcapngWriter`) for offline forensic analysis in Wireshark.
- **On-Device Intrusion Detection System (IDS)**
  - Deep inspection and anomaly/signature detection (`IdsEngine`) integrated directly into the VPN pipeline with a dedicated tactical alert dashboard.
- **Bluetooth & BLE Threat Monitoring**
  - Active BLE threat detection (`BleThreatMonitor`) paired with a built-in **BTSnoop** HCI log parser (`BtSnoopParser`) for auditing local Bluetooth activity.
- **RF Spectrum Analyzer (RTL-SDR)**
  - USB OTG integration for RTL-SDR dongles (`RtlSdrUsbManager`) with an on-device Radix-2 FFT engine (`Radix2FftEngine`) for real-time RF spectrum visualization.
- **Near-IR Spotter**
  - Optical near-infrared anomaly detection (`NearIrAnalyzer`) to assist in spotting hidden IR emitters and surveillance hardware.

## Architecture

- **UI:** Jetpack Compose tactical dark interface with custom typography (`Space Grotesk`, `IBM Plex Sans`, `JetBrains Mono`) and MVVM state management.
- **Data Layer:** Local Room database (`FirewallDatabase`), DAOs, and `PreferencesRepository` for offline-first rule and telemetry persistence.
- **Engines:** Modular pure-Kotlin engines separated by domain (`network`, `bluetooth`, `ir`, `rf`) for testability and low-overhead analysis.

## Disclaimer

This tool is intended for defensive monitoring, authorized security research, and personal device hardening. Ensure compliance with local laws and regulations when capturing network traffic or analyzing RF/Bluetooth signals.
