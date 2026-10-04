#!/bin/bash
# 构建 LSPosed 模块 APK（不依赖 Gradle / Android Studio）
#
# 依赖：JDK 17、Android SDK Build-Tools（d8 / aapt2 / zipalign / apksigner）、android.jar（API 34）
# 查找顺序：
#   1) 环境变量 JAVA_HOME、ANDROID_HOME / ANDROID_SDK_ROOT、BUILD_TOOLS、ANDROID_JAR
#   2) 仓库上级目录的 toolchain/{jdk-*,android-*,android-34-*}
#
# 输出：MztRootHide.apk（LSPosed 模块，包名 com.mzt.roothide）
#
# 注意：本项目已验证「LSPosed 注入会被闽政通壳识别并主动 SIGSEGV」，
#       该 APK 仅作为研究/历史存档保留，实际可用方案见 zygisk-module/。
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"
MOD="$ROOT/lsposed-module"
OUT="$ROOT/build/lsposed"

find_jdk() {
  local c
  [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/javac" ] && { echo "$JAVA_HOME"; return; }
  c=$(ls -d "$ROOT"/../toolchain/jdk-* 2>/dev/null | head -1 || true)
  [ -n "$c" ] && [ -d "$c/Contents/Home" ] && { echo "$c/Contents/Home"; return; }
  [ -n "$c" ] && { echo "$c"; return; }
  c=$(/usr/libexec/java_home -v 17 2>/dev/null || true)
  [ -n "$c" ] && { echo "$c"; return; }
  return 0   # 找不到也必须返回 0：set -e 下 $() 的非零状态会让整个脚本静默退出
}

find_sdk() {
  local c
  for c in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}"; do
    [ -n "$c" ] && [ -d "$c" ] && { echo "$c"; return; }
  done
  for c in "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
    [ -d "$c" ] && { echo "$c"; return; }
  done
  return 0   # 找不到也必须返回 0：set -e 下 $() 的非零状态会让整个脚本静默退出
}

JDK=$(find_jdk)
SDK=$(find_sdk)
BT="${BUILD_TOOLS:-}"
if [ -z "$BT" ] && [ -n "${SDK:-}" ]; then
  BT=$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1 || true)
fi
if [ -z "$BT" ] && [ -d "$ROOT/../toolchain/android-14" ]; then
  BT="$ROOT/../toolchain/android-14"
fi
AJAR="${ANDROID_JAR:-}"
if [ -z "$AJAR" ] && [ -n "${SDK:-}" ]; then
  AJAR=$(ls -d "$SDK"/platforms/android-34*/android.jar 2>/dev/null | tail -1 || true)
fi
if [ -z "$AJAR" ] && [ -d "$ROOT/../toolchain/android-34-ext12" ]; then
  AJAR="$ROOT/../toolchain/android-34-ext12/android.jar"
fi

for v in JDK BT AJAR; do
  if [ -z "${!v:-}" ]; then echo "错误：无法定位 $v（可用 JAVA_HOME / BUILD_TOOLS / ANDROID_JAR 指定）。" >&2; exit 1; fi
done

export JAVA_HOME="$JDK"
export PATH="$JDK/bin:$PATH"
echo "JDK = $JDK"
echo "BUILD_TOOLS = $BT"
echo "android.jar = $AJAR"

rm -rf "$OUT"; mkdir -p "$OUT/classes" "$OUT/dex" "$OUT/pkg"

echo "== 1) javac 编译（模块 + Xposed API 存根）=="
"$JDK/bin/javac" -encoding UTF-8 -source 8 -target 8 -nowarn \
  -bootclasspath "$AJAR" -classpath "$AJAR" \
  -d "$OUT/classes" \
  $(find "$MOD/src" "$MOD/stubs" -name '*.java')

echo "== 2) d8 只把模块类打成 dex（存根不进包）=="
"$BT/d8" --min-api 24 --lib "$AJAR" --output "$OUT/dex" \
  $(find "$OUT/classes/com" -name '*.class')
ls -la "$OUT/dex"

echo "== 3) aapt2 link 生成 manifest 资源包 =="
"$BT/aapt2" link -I "$AJAR" --manifest "$MOD/AndroidManifest.xml" \
  --min-sdk-version 24 --target-sdk-version 34 -o "$OUT/pkg/base.apk" 2>&1 | tail -5

echo "== 4) 塞入 classes.dex 与 assets/xposed_init =="
cp "$OUT/dex/classes.dex" "$OUT/pkg/classes.dex"
mkdir -p "$OUT/pkg/assets"
cp "$MOD/assets/xposed_init" "$OUT/pkg/assets/xposed_init"
( cd "$OUT/pkg" && zip -q -X base.apk classes.dex assets/xposed_init && unzip -l base.apk )

echo "== 5) zipalign + 签名 =="
"$BT/zipalign" -f -p 4 "$OUT/pkg/base.apk" "$OUT/pkg/aligned.apk"
KS="$ROOT/build/mzt.jks"
if [ ! -f "$KS" ]; then
  "$JDK/bin/keytool" -genkeypair -keystore "$KS" -alias mzt -keyalg RSA -keysize 2048 \
    -validity 10000 -storepass android -keypass android -dname "CN=MZT,O=RootHide,C=CN" 2>/dev/null
fi
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
  --v1-signing-enabled true --v2-signing-enabled true \
  --out "$ROOT/MztRootHide.apk" "$OUT/pkg/aligned.apk"
"$BT/apksigner" verify --print-certs "$ROOT/MztRootHide.apk" 2>&1 | head -5 || true
ls -la "$ROOT/MztRootHide.apk"
echo "BUILD OK"
