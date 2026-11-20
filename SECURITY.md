# Security Policy

**Another Android Firewall+** is a defensive security and telemetry tool. Because this application processes untrusted network packets, Bluetooth HCI logs, USB OTG streams, and sensitive local captures, we take security vulnerabilities seriously and welcome responsible disclosure from the security community.

---

## Supported Versions

Security patches are provided for the latest tagged release. Pre-release snapshots and debug builds are supported on a best-effort basis and are not recommended for production use.

| Version | Supported |
| ------- | --------- |
| Latest tagged release | Yes |
| `main` (pre-release) | Best-effort |
| Older releases / debug builds | No |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

### Preferred Channel: GitHub Private Vulnerability Reporting
1. Navigate to the **Security** tab of this repository.
2. Select **Advisories** and click **Report a vulnerability**.
3. Submit your report directly through GitHub's private advisory form.

### Alternative Channel: Direct Email
If you cannot use GitHub Security Advisories, email:
* **Contact:** `security@<your-domain>` *(replace before committing)*
* **PGP Fingerprint:** `<YOUR_PGP_FINGERPRINT>` *(optional)*

### What to Include
* **Affected Component:** e.g., `PacketParser`, `IdsEngine`, `BtSnoopParser`, `FirewallVpnService`, `VpnTelemetryBus`, `RtlSdrUsbManager`, or `FirewallDatabase`.
* **Environment:** App version, Android version, device model, and whether the device is stock or modified.
* **Impact:** Describe the security consequence (e.g., firewall rule bypass, VPN fail-open crash, local data leak, OOM/CPU DoS).
* **Reproduction:** Step-by-step instructions and a minimal Proof of Concept (e.g., synthetic packet hex, minimal truncated `.pcapng`/`.btsnoop` sample, or `adb` intent command).

> **Privacy Reminder:** Please **sanitize or synthesize** any `.pcapng`, `.btsnoop`, or log files before sending. Never attach raw captures containing personal credentials, session cookies, private IPs, or real device MAC addresses.

---

## Response & Disclosure Timeline

We follow a **90-day coordinated vulnerability disclosure** model:
* **Acknowledgment:** Within **72 hours** of receiving your report.
* **Initial Triage:** Within **7 business days**, including severity assessment and confirmation of reproducibility.
* **Remediation & Advisory:** Once a fix is verified, we will publish a patched release and a GitHub Security Advisory (with CVE assignment where applicable) and credit you if desired.

---

## Scope

### In Scope
We are especially interested in vulnerabilities affecting these trust boundaries:

1. **VPN & Packet Processing Pipeline (`FirewallVpnService`, `PacketParser`, `FirewallRuleEngine`, `IdsEngine`, `PcapngWriter`, `AppLabelResolver`, `VpnTelemetryBus`)**
   * Malformed IPv4/IPv6/TCP/UDP/DNS/TLS packets causing uncaught exceptions, VPN crashes, or **fail-open** traffic leaks.
   * Algorithmic complexity attacks (ReDoS, infinite option/extension loops, DNS pointer cycles, telemetry queue flooding) causing CPU, memory, or battery exhaustion.
   * Firewall policy bypasses or UID/app attribution spoofing.
2. **Bluetooth & Forensic Parsers (`BleThreatMonitor`, `BtSnoopParser`)**
   * Malicious BLE advertisements or crafted BTSnoop/HCI logs triggering out-of-memory errors, infinite TLV loops, or parser crashes.
3. **Hardware & Sensor Interfaces (`RtlSdrUsbManager`, `usb_device_filter.xml`, `Radix2FftEngine`, `NearIrAnalyzer`)**
   * Unsafe USB OTG intent handling, unauthorized device access, or buffer handling flaws in IQ/FFT processing.
4. **Data Privacy, Storage & IPC (`FirewallDatabase`, `PreferencesRepository`, `AndroidManifest.xml`, `backup_rules.xml`, `data_extraction_rules.xml`)**
   * Unauthorized access to captured `.pcapng` files, IDS alerts, or firewall rules by other installed apps.
   * Accidental leakage of sensitive local telemetry via Android cloud backups or device-to-device transfers.
   * Exported component/intent hijacking or privilege escalation from an unprivileged third-party app.
5. **Build & Supply Chain Integrity**
   * Reproducible build discrepancies, APK signing issues, or exploitable third-party dependency vulnerabilities.

### Out of Scope
* Attacks requiring an already rooted device, unlocked bootloader with physical access, or active `adb` shell privileges (unless demonstrating a sandbox escape from an unprivileged app).
* Standard Android `VpnService` platform limitations (such as traffic outside the active user profile or OS-level captive portal probes).
* Heuristic false positives or false negatives in IDS, BLE, or Near-IR detection without a concrete bypass or denial-of-service vector.
* Hardware-level optical limitations (e.g., stock smartphone camera IR-cut filters limiting Near-IR sensitivity).

---

## Hardening Recommendations for Users

* **Prevent Fail-Open Leaks:** In Android **Settings - Network & internet - VPN**, enable both **Always-on VPN** and **Block connections without VPN** for Another Android Firewall+.
* **Verify Official Releases:** Before installing a release APK, verify its signing certificate fingerprint with `apksigner`:

```bash
apksigner verify --print-certs another-android-firewall-release.apk
```

* **Expected SHA-256 Certificate Digest:** `<INSERT_YOUR_RELEASE_CERT_SHA256_HERE>`

---

## Safe Harbor

We support good-faith security research. If you make a good-faith effort to comply with this policy—testing only on your own devices and networks, avoiding harm to others, and reporting findings privately—we will not pursue legal action against you for your research.
