#!/bin/bash
# 构建 Zygisk 原生模块（Magisk 模块 zip）
#
# 依赖：Android NDK r26d（或任意 r25+），需提供 aarch64-linux-android*-clang++
# NDK 查找顺序：
#   1) 环境变量 ANDROID_NDK_HOME / ANDROID_NDK_ROOT
#   2) 仓库上级目录的 toolchain/android-ndk-*
#   3) $HOME/Library/Android/sdk/ndk/*（macOS）/ $HOME/Android/Sdk/ndk/*（Linux）
#
# 输出：MztKillModule.zip（含 module.prop / service.sh / uninstall.sh / zygisk/arm64-v8a.so）
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$PWD"
MOD="$ROOT/zygisk-module"
OUT_ZIP="$ROOT/MztKillModule.zip"

find_ndk() {
  local c
  for c in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
    [ -n "$c" ] && [ -d "$c" ] && { echo "$c"; return; }
  done
  c=$(ls -d "$ROOT"/../toolchain/android-ndk-* 2>/dev/null | head -1 || true)
  [ -n "$c" ] && { echo "$c"; return; }
  c=$(ls -d "$HOME"/Library/Android/sdk/ndk/* 2>/dev/null | tail -1 || true)
  [ -n "$c" ] && { echo "$c"; return; }
  c=$(ls -d "$HOME"/Android/Sdk/ndk/* 2>/dev/null | tail -1 || true)
  [ -n "$c" ] && { echo "$c"; return; }
  return 0   # 找不到也必须返回 0：set -e 下 $() 的非零状态会让整个脚本静默退出
}

NDK=$(find_ndk)
if [ -z "${NDK:-}" ]; then
  echo "错误：找不到 Android NDK。请设置 ANDROID_NDK_HOME 后重试。" >&2
  exit 1
fi

TC=$(ls -d "$NDK"/toolchains/llvm/prebuilt/* 2>/dev/null | head -1 || true)
CXX="$TC/bin/aarch64-linux-android26-clang++"
[ -x "$CXX" ] || CXX=$(ls "$TC"/bin/aarch64-linux-android*-clang++ 2>/dev/null | head -1 || true)
if [ -z "${CXX:-}" ] || [ ! -x "$CXX" ]; then
  echo "错误：在 $TC/bin 下找不到 aarch64 clang++。" >&2
  exit 1
fi

echo "NDK = $NDK"
echo "CXX = $CXX"

mkdir -p "$MOD/zygisk"
# 必须 -static-libstdc++：应用进程里没有 libc++_shared.so，动态依赖会导致 dlopen 失败，
# Magisk 会在模块目录写入 zygisk/unloaded 标记。
"$CXX" -shared -fPIC -O2 -std=c++17 -fno-exceptions -fno-rtti -static-libstdc++ \
  -I"$MOD/src" -I"$MOD/third_party/zygisk" \
  -o "$MOD/zygisk/arm64-v8a.so" "$MOD/src/mztkill.cpp" -llog

ls -la "$MOD/zygisk/arm64-v8a.so"
file "$MOD/zygisk/arm64-v8a.so" 2>/dev/null || true

rm -f "$OUT_ZIP"
( cd "$MOD" && zip -q -r "$OUT_ZIP" module.prop service.sh uninstall.sh zygisk )
echo "已生成 $OUT_ZIP"
unzip -l "$OUT_ZIP"
