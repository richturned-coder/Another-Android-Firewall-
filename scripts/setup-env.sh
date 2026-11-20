#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_SDK_DIR="${ANDROID_HOME:-$HOME/Android/Sdk}"
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"

# 1. Ensure gradlew is executable
if [ -f "$REPO_ROOT/gradlew" ]; then
  chmod +x "$REPO_ROOT/gradlew"
fi

# 2. Detect JDK (prefer JDK 21 if available, otherwise JDK 17 or default java)
if [ -z "${JAVA_HOME:-}" ] || [ ! -x "${JAVA_HOME}/bin/java" ]; then
  if [ -d /usr/lib/jvm/java-21-openjdk-amd64 ]; then
    JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"
  elif [ -d /usr/lib/jvm/java-17-openjdk-amd64 ]; then
    JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
  elif command -v java >/dev/null 2>&1; then
    JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")"
  fi
fi

# 3. Persist environment exports idempotently in ~/.bashrc (works in non-interactive shells)
touch "$HOME/.bashrc"
sed -i '/case \$- in/,/esac/d' "$HOME/.bashrc" 2>/dev/null || true

persist_export() {
  local line="$1"
  grep -qxF "$line" "$HOME/.bashrc" || echo "$line" >> "$HOME/.bashrc"
}

if [ -n "${JAVA_HOME:-}" ] && [ -d "$JAVA_HOME" ]; then
  export JAVA_HOME
  export PATH="$JAVA_HOME/bin:$PATH"
  persist_export "export JAVA_HOME=$JAVA_HOME"
  persist_export 'export PATH="$JAVA_HOME/bin:$PATH"'
fi

export ANDROID_HOME="$ANDROID_SDK_DIR"
export ANDROID_SDK_ROOT="$ANDROID_SDK_DIR"
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"
persist_export "export ANDROID_HOME=$ANDROID_SDK_DIR"
persist_export "export ANDROID_SDK_ROOT=$ANDROID_SDK_DIR"
persist_export 'export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"'

# 4. Generate gitignored debug.keystore matching app/build.gradle.kts debugConfig
if [ ! -f "$REPO_ROOT/debug.keystore" ] && command -v keytool >/dev/null 2>&1; then
  keytool -genkeypair -noprompt \
    -keystore "$REPO_ROOT/debug.keystore" \
    -storepass android \
    -alias androiddebugkey \
    -keypass android \
    -keyalg RSA \
    -keysize 2048 \
    -validity 10000 \
    -dname "CN=Android Debug,O=Android,C=US"
fi

# 5. Configure Gradle JVM proxy properties from HTTP_PROXY / HTTPS_PROXY when present
mkdir -p "$HOME/.gradle"
GRADLE_PROPS="$HOME/.gradle/gradle.properties"
touch "$GRADLE_PROPS"
python3 - "$GRADLE_PROPS" <<'PY'
import os, sys
from urllib.parse import urlparse

props_path = sys.argv[1]
http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or ""
https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""

start_marker = "# BEGIN managed-proxy-config"
end_marker = "# END managed-proxy-config"

with open(props_path, "r", encoding="utf-8") as f:
    lines = f.read().splitlines()

filtered = []
in_block = False
for line in lines:
    if line.strip() == start_marker:
        in_block = True
        continue
    if line.strip() == end_marker:
        in_block = False
        continue
    if not in_block:
        filtered.append(line)

block = []
if http_proxy or https_proxy:
    block.append(start_marker)
    for scheme, raw in [("http", http_proxy), ("https", https_proxy)]:
        if not raw:
            continue
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        if parsed.hostname:
            block.append(f"systemProp.{scheme}.proxyHost={parsed.hostname}")
        if parsed.port:
            block.append(f"systemProp.{scheme}.proxyPort={parsed.port}")
    if no_proxy:
        non_proxy = "|".join(h.strip() for h in no_proxy.split(",") if h.strip())
        if non_proxy:
            block.append(f"systemProp.http.nonProxyHosts={non_proxy}")
            block.append(f"systemProp.https.nonProxyHosts={non_proxy}")
    block.append(end_marker)

out = "\n".join(filtered + ([""] if filtered and block else []) + block).rstrip() + ("\n" if (filtered or block) else "")
with open(props_path, "w", encoding="utf-8") as f:
    f.write(out)
PY

# 6. Install Android SDK & warm Gradle wrapper if outbound registries are permitted
DL_STATUS="$(curl -sI -o /dev/null -w '%{http_code}' --max-time 8 "$CMDLINE_TOOLS_URL" || echo "000")"
if [ "$DL_STATUS" = "200" ] || [ "$DL_STATUS" = "302" ]; then
  SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
  if [ ! -x "$SDKMANAGER" ]; then
    mkdir -p "$ANDROID_HOME/cmdline-tools"
    TMP_ZIP="$(mktemp /tmp/cmdline-tools-XXXXXX.zip)"
    TMP_DIR="$(mktemp -d /tmp/cmdline-tools-XXXXXX)"
    trap 'rm -rf "$TMP_ZIP" "$TMP_DIR"' EXIT
    curl -fsSL "$CMDLINE_TOOLS_URL" -o "$TMP_ZIP"
    unzip -q "$TMP_ZIP" -d "$TMP_DIR"
    rm -rf "$ANDROID_HOME/cmdline-tools/latest"
    mv "$TMP_DIR/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
    rm -rf "$TMP_ZIP" "$TMP_DIR"
    trap - EXIT
  fi

  SDK_PROXY_ARGS=()
  PROXY_RAW="${HTTPS_PROXY:-${https_proxy:-${HTTP_PROXY:-${http_proxy:-}}}}"
  if [ -n "$PROXY_RAW" ]; then
    read -r P_HOST P_PORT < <(python3 -c '
import sys
from urllib.parse import urlparse
u = urlparse(sys.argv[1] if "://" in sys.argv[1] else "http://" + sys.argv[1])
print(u.hostname or "", u.port or "")
' "$PROXY_RAW")
    if [ -n "${P_HOST:-}" ] && [ -n "${P_PORT:-}" ]; then
      SDK_PROXY_ARGS=(--proxy=http "--proxy_host=$P_HOST" "--proxy_port=$P_PORT")
    fi
  fi

  yes | "$SDKMANAGER" --sdk_root="$ANDROID_HOME" "${SDK_PROXY_ARGS[@]}" --licenses >/dev/null 2>&1 || true
  "$SDKMANAGER" --sdk_root="$ANDROID_HOME" "${SDK_PROXY_ARGS[@]}" \
    "platform-tools" \
    "platforms;android-36" \
    "platforms;android-36.1" \
    "build-tools;36.0.0"

  printf 'sdk.dir=%s\n' "$ANDROID_HOME" > "$REPO_ROOT/local.properties"

  GRADLE_STATUS="$(curl -sI -o /dev/null -w '%{http_code}' --max-time 8 "https://services.gradle.org/" || echo "000")"
  if [ "$GRADLE_STATUS" = "200" ] || [ "$GRADLE_STATUS" = "301" ] || [ "$GRADLE_STATUS" = "302" ]; then
    (cd "$REPO_ROOT" && ./gradlew --version --no-daemon)
  fi
else
  echo "[setup-env] Outbound access to dl.google.com returned HTTP ${DL_STATUS}; skipping Android SDK download."
  echo "[setup-env] Local JDK (${JAVA_HOME:-unknown}), Gradle proxy config, and debug.keystore are ready."
  echo "[setup-env] Allow dl.google.com, maven.google.com, services.gradle.org, downloads.gradle.org, plugins.gradle.org, plugins-artifacts.gradle.org, and repo1.maven.org to install the Android SDK locally."
fi
