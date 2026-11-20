"""
解析 airodump 产生的 csv 文件
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class AccessPoint:
    """
    无线接入点
    """
    bssid: str
    channel: Optional[int]
    privacy: str
    cipher: str
    authentication: str
    power: Optional[int]
    id_length: Optional[int]
    essid: Optional[bytes]

@dataclass
class Station:
    """
    无线接入点下的设备
    """
    mac: str
    power: Optional[int]
    packets: Optional[int]
    bssid: Optional[str]
    probed: List[bytes] = field(default_factory=list)


@dataclass
class SSIDGroup:
    """一个ssid下的一组 AP """
    essid: Optional[bytes]
    aps: List[AccessPoint] = field(default_factory=list)

    @property
    def best(self) -> AccessPoint:
        """信号最强的 AP。"""
        return max(self.aps, key=lambda a: (a.power if a.power is not None else -999))

    @property
    def channels(self) -> List[int]:
        """所有 AP 的 channel , 去重排序"""
        return sorted({a.channel for a in self.aps if a.channel is not None})



@dataclass
class ScanResult:
    """
    扫描结果
    """
    aps: List[AccessPoint]
    stations: List[Station]

    def group_bssid(self) -> List[SSIDGroup]:
        """
        按照 SSID 聚合 BSSID
        """
        buckets: Dict[Optional[bytes], List[AccessPoint]] = defaultdict(list)
        for ap in self.aps:
            essid = ap.essid if ap.essid else ("hidden", ap.bssid)
            buckets[essid].append(ap)

        groups: List[SSIDGroup] = []
        for essid, aps in buckets.items():
            aps_sorted = sorted(aps, key=lambda ap: (ap.power if ap.power is not None else -999), reverse=True)
            groups.append(SSIDGroup(aps_sorted[0].essid, aps_sorted))

        groups.sort(
            key=lambda group: (group.best.power if group.best.power is not None else -999),
            reverse=True
        )

        return groups



def parse_csv(csv_path: str) -> ScanResult:
    with open(csv_path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8", errors="surrogateescape")
    result = parse_text(text)
    return result

            
def parse_text(text: str) -> ScanResult:
    aps, stations = [], []
    section = None # "ap" or "station"
    for line in text.splitlines():
        line = line.strip()

        if not line:
            # 空行，从 ap 进入 station
            if section == "ap":
                section = "station"

            continue

        if section is None:
            # 首行判断, 判断是 ap 还是 station
            if "channel" in line and "Speed" in line:
                section = "ap"

            elif "Station MAC" in line:
                section = "station"


        if section == "ap":
            ap = _parse_ap_line(line)
            if ap:
                aps.append(ap)
        
        else:
            station = _parse_station_line(line)
            if station:
                stations.append(station)

    return ScanResult(aps, stations)

            
def _parse_ap_line(line: str) -> dict:
    """处理 ap 行"""
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 15:
        return
    if not _looks_like_mac(parts[0]):
        return

    bssid = parts[0]
    channel = _to_int(parts[3])
    privacy = parts[5]
    cipher = parts[6]
    authentication = parts[7]
    power = _to_power(parts[8])
    id_length = _to_int(parts[12])

    # essid 比较特殊, SSID 里的逗号不转义, 且 airodump-ng 会在 SSID 有前导/尾随空格时加引号，所以不能 strip
    essid = ",".join(parts[13:len(parts) - 1]).strip('"')
    essid = essid.replace("\x00", "")
    essid_bytes = essid.encode("utf-8", errors="surrogateescape") if essid else None

    if essid_bytes is not None and id_length is not None:
        if len(essid_bytes) != id_length:
            return

    if id_length == 0:
        essid_bytes = None

    return AccessPoint(
        bssid, channel, privacy, cipher, authentication, power, id_length, essid_bytes
    )



def _parse_station_line(line: str) -> dict:
    """处理 station 行"""
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 6:
        return
    if not _looks_like_mac(parts[0]):
        return

    station_mac = parts[0]
    power = _to_power(parts[3])
    packets = _to_int(parts[4])
    bssid = parts[5] if _looks_like_mac(parts[5]) else None
    probed_essids = ",".join(parts[6:])

    probed = [
        p.strip().encode("utf-8", errors="surrogateescape")
        for p in probed_essids.split(",")
        if p.strip()
    ]

    return Station(station_mac, power, packets, bssid, probed)



# 工具
_MAC_RE = __import__("re").compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_TIME_RE = __import__("re").compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")

def _looks_like_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac))


def _to_int(s: str) -> Optional[int]:
    s = s.strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def _to_power(text: str) -> Optional[int]:
    """airodump 用 -1 表示信号未知 —— 归一成 None（AP 段和 Station 段都用这个）"""
    p = _to_int(text)
    return None if p == -1 else p


