"""
适配层
前端调用底层攻击函数的部分
"""

from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Optional

from .errors import WifiHackingToolError


# 通用序列化
def _jsonable(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(o) for o in obj]
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("utf-8", errors="replace")

    return str(obj)


# 适配层
def run_iface_list() -> Dict[str, Any]:
    from .iface import iface_list_command
    result = iface_list_command()
    return {
        "ifaces": [{"name": i.name, "mode": i.mode, "phy": i.phy} for i in result],
        "count": len(result),
    }

def run_iface_mode(iface: str, mode: str) -> Dict[str, Any]:
    from .iface import set_monitor_mode, set_managed_mode
    if mode == "monitor":
        result = set_monitor_mode(iface)
    elif mode == "managed":
        result = set_managed_mode(iface)
    else:
        raise WifiHackingToolError(
            f"未知模式 {mode!r}（只支持 monitor / managed）", return_code=2
        )
    
    return {"iface": iface, "mode": mode, "changed": result}




def run_scan(iface: str, duration: int = 10, output_dir: Optional[str] = None) -> Dict[str, Any]:
    from wifi_core.scan import scan_command
    result = scan_command(iface, duration, output_dir)
    return {
        "ap_count": len(result.aps),
        "station_count": len(result.stations),
        "aps": _jsonable(result.aps),
        "stations": _jsonable(result.stations),
    }

def run_capture(
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
) -> Dict[str, Any]:
    from wifi_core.capture_handshake_packet import capture_command
    result = capture_command(
        bssid, iface, channel, output_dir, duration, poll_interval, deauth, station, count
    )
    return {
        "bssid": result.bssid,
        "channel": result.channel,
        "cap_path": result.cap_path,
        "handshakes": result.handshakes,
        "packets": result.packets,
        "duration": round(result.duration, 2),
        "got_handshake": result.got_handshake,
    }

def run_pmkid(
    bssid: str,  # 目标网络的BSSID（MAC地址）
    iface: str,  # 使用的网络接口
    duration: int = 60,
    channel: Optional[int] = None,
    output_dir: Optional[str] = None
) -> Dict[str, Any]:
    from wifi_core.pmkid import pmkid_command
    result = pmkid_command(bssid, iface, duration, channel, output_dir)
    return {
        "bssid": result.bssid,
        "channel": result.channel,
        "pcapng_path": result.pcapng_path,
        "hash_path": result.hash_path,
        "pmkid_counts": result.pmkid_counts,
        "eapol_counts": result.eapol_counts,
        "message": result.message,
        "got_hash": result.got_hash(),
        "got_pmkid": result.got_pmkid()
    }

def run_crack(
    hash_file: str,
    wordlist: str,
    bssid: Optional[str] = None,
    timeout: Optional[int] = None,
    output_dir: Optional[str] = None
) -> Dict[str, Any]:
    from wifi_core.crack import crack_command
    result = crack_command(hash_file, wordlist, bssid, timeout, output_dir)
    return {
        "hash_file": result.hash_file,
        "wordlist": result.wordlist,
        "elapsed": round(result.elapsed, 1),
        "speed": round(result.speed, 1) if result.speed else None,
        "return_code": result.return_code,
        "message": result.message,
        "password": result.password,
        "hash_count": result.hash_count,
        "cracked": result.cracked
    }


def run_chaos(bssid: str, iface: str, channel: int, station: str = "all",
              duration: int = 300) -> Dict[str, Any]:
    """让目标持续断网"""
    from wifi_core.chaos import chaos_command

    r = chaos_command(bssid, iface, channel, station, duration)
    return {
        "bssid": r.bssid,
        "station": r.station,
        "elapsed": round(r.elapsed, 1),
        "sent": r.sent,
        "log_path": r.log_path,
        "message": r.message,
    }