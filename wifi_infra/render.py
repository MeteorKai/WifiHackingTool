from typing import List, Optional

from .parse import ScanResult, Station



def _ssid_text(essid: Optional[bytes]) -> str:
    if not essid:
        return "(hidden)"
    return essid.decode("utf-8", errors="backslashreplace") # 解析要保真，显示要可读


def render_scan(result: ScanResult) -> None:
    render_groups(result)
    render_station(result.stations)

            
def render_groups(result: ScanResult) -> None:
    groups = result.group_bssid()
    for group in groups:
        chs = ",".join(str(c) for c in group.channels) or "-"
        best = group.best
        print(f"\n{_ssid_text(group.essid):<28}×{len(group.aps):<3} 信道 {chs:<8} 最强 {best.power}")
        for ap in group.aps:
            ch = str(ap.channel) if ap.channel else "-"
            enc = ap.privacy or "OPN"
            pwr = str(ap.power) if ap.power is not None else "-"
            print(f"    {ap.bssid:<18}{ch:<4}{enc:<10}{pwr}")



def render_station(stations: List[Station]) -> None:
    if not stations:
        return
    print(f"\n{'Station MAC':<18}{'PWR':<6}{'BSSID':<18}{'Probed'}")
    for sta in sorted(
        stations,
        key=lambda sta: sta.power if sta.power is not None else -999,
        reverse=True
    ):
        pwr = str(sta.power) if sta.power is not None else "-"
        bssid = sta.bssid if sta.bssid else "(not associated)"
        probed = ",".join(p.decode("utf-8", errors="backslashreplace") for p in sta.probed)
        print(f"{sta.mac:<18}{pwr:<6}{bssid:<18}{probed}")


