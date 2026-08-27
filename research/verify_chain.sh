#!/usr/bin/env bash
#
# verify_chain.sh — macOS 侧真机验证脚本（Exploit 链状态检查）
#
# 用途：
#   1. 确保 lara.forceOffsets 已设（研究覆盖，26.1+ 必须）
#   2. 构建 + 安装 ipa 到已连接设备
#   3. 启动 app 触发 ds_run()，抓设备控制台日志中的链标签
#   4. 把每条链的"校准点"输出整理成可直接阅读的结论
#
# 依赖：Xcode 命令行工具、已信任的设备、ideviceinstaller 或 muxd/ios-deploy
# 用法：
#   ./verify_chain.sh [<ios_version>]    默认列出所有匹配设备
#
set -euo pipefail

CWD="$(cd "$(dirname "$0")/.." && pwd)"
IPA="${IPA:-$CWD/build/lara.ipa}"
BUNDLE_ID="${BUNDLE_ID:-com.rooootdev.lara}"   # 以实际工程为准
FORCE_KEY="${FORCE_KEY:-lara.forceOffsets}"

echo "== lara exploit-chain 真机验证 =="
echo "workdir: $CWD"

# ---- 1. forceOffsets 通知 -------------------------------------------
echo
echo "[1/4] 提醒：本机 26.1+ 必须设 $FORCE_KEY=true"
echo "      (在 app 内 Settings 或 UserDefaults 写入；否则 hasOffsets=false 且 vfs/autopipeline 不启动)"

# ---- 2. 构建（macOS only） -----------------------------------------
if [ -x "$CWD/scripts/build_ipa.sh" ]; then
    echo "[2/4] 构建 ipa（可选，若已构建可设 IPA= 跳过）"
    if [ ! -f "$IPA" ]; then
        (cd "$CWD" && ./scripts/build_ipa.sh) || { echo "构建失败"; exit 1; }
    fi
else
    echo "[2/4] 未找到 scripts/build_ipa.sh，跳过构建（假设 $IPA 已存在）"
fi

# ---- 3. 安装 + 启动 ------------------------------------------------
DEVICE="${DEVICE:-}"
if [ -n "$DEVICE" ]; then
    echo "[3/4] 安装到设备 $DEVICE (需 ideviceinstaller)"
    ideviceinstaller -u "$DEVICE" -i "$IPA" || true
    ideviceinstaller -u "$DEVICE" -l | grep -i lara || true
else
    echo "[3/4] 未指定 DEVICE，跳过安装（仅检查日志）。设备列表："
    idevice_id -l 2>/dev/null || xcrun devicectl list devices 2>/dev/null || echo "      (无 idevice 工具，手动安装后继续)"
fi

# ---- 4. 抓取链标签日志 ---------------------------------------------
echo
echo "[4/4] 采集 10 秒设备日志中的链标签（Ctrl-C 提前结束）"
TMPLOG="$(mktemp)"
if command -v idevicesyslog >/dev/null 2>&1; then
    timeout 10 idevicesyslog > "$TMPLOG" 2>&1 || true
else
    log stream --predicate 'process == "lara"' --style compact --timeout 10s > "$TMPLOG" 2>&1 || \
    log show --last 10m --predicate 'process == "lara"' > "$TMPLOG" 2>&1 || true
fi

echo "---- 匹配结果 ----"
grep -E '\(chainrouter\)|\(20626\)|\(20698\)|\(264\)|\(266\)|exploit (success|failed)' "$TMPLOG" \
    | tail -40 || echo "（未抓到链标签：app 可能未启动或 forceOffsets 未设）"

echo
echo "---- 校准点速查 ----"
grep -E 'escalation stage requires|OOB probe failed|not marking ready|staged' "$TMPLOG" \
    | tail -20 || echo "（无校准点输出）"
rm -f "$TMPLOG"

echo
echo "完成。对照 docs/EXPLOIT_CHAIN_INTEGRATION.md 的 §3 判断下一步。"