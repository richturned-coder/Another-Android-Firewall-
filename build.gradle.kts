// Top-level build file where you can add configuration options common to all sub-projects/modules.
buildscript {
  dependencies {
    constraints {
      // AGP 9.1.1 (sdk-common, builder, apkzlib) transitively pulls Bouncy Castle 1.79, which is
      // vulnerable to CVE-2026-8763 (GHSA-9pwp-9qqc-pr26: Name Constraints bypass via trailing dot
      // in rfc822Name and URI). Align all jdk18on artifacts to patched 1.87.
      classpath(libs.bouncycastle.bcprov) {
        because("Remediate CVE-2026-8763 (GHSA-9pwp-9qqc-pr26) in AGP buildscript classpath")
      }
      classpath(libs.bouncycastle.bcpkix) {
        because("Align bcpkix-jdk18on with patched bcprov-jdk18on (CVE-2026-8763)")
      }
      classpath(libs.bouncycastle.bcutil) {
        because("Align bcutil-jdk18on with patched bcprov-jdk18on (CVE-2026-8763)")
      }
    }
  }
}

plugins {
  alias(libs.plugins.android.application) apply false
  alias(libs.plugins.kotlin.compose) apply false
  alias(libs.plugins.google.devtools.ksp) apply false
  alias(libs.plugins.secrets) apply false
  alias(libs.plugins.google.services) apply false
}
