"""
使用 airodump-ng 抓 CSV
"""

import os
import subprocess
import sys
import tempfile
import time
from typing import List, Optional

from wifi_infra.errors import WifiHackingToolError
from wifi_infra.iface import IfaceError, require_monitor_mode
from wifi_infra.parse import SSIDGroup, ScanResult, parse_csv
from wifi_infra.runner import run_command, OutResult, start_process
from wifi_infra.utils import require_linux




def check_airodump():
    """检查 airodump-ng 是否存在"""
    result = run_command(['airodump-ng', '-h'], timeout=10)
    if result.outResult == OutResult.NOTFOUND:
        raise IfaceError("[工具缺失] 请先安装 airodump-ng", return_code=result.exit_code())
    
def _count_aps_so_far(csv_path: str) -> int:
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return 0

    count = 0
    for line in text.splitlines():
        if "Station MAC" in line:
            break
        parts = line.split(",")
        if len(parts) > 5 and "BSSID" not in parts[0] and parts[0].strip().count(":") == 5:
            count += 1
    return count

    

def scan_command(iface: str, duration: int = 10, output_dir: Optional[str] = None) -> ScanResult:
    """使用 airodump-ng 执行扫描命令"""

    require_linux("airodump-ng")
    check_airodump()
    require_monitor_mode(iface)

    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="WifiHackingTool-")
    else:
        os.makedirs(output_dir, exist_ok=True)

    prefix = os.path.join(output_dir, "scan")
    print(f"[扫描结果保存位置]: {output_dir}", file=sys.stderr)
    csv_path = f"{prefix}-01.csv"

    # run_command会阻塞到命令执行结束，而这里的情况不同
    handler = start_process(
        ['airodump-ng', '-w', prefix, '--output-format', 'csv', iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    try:
        started = time.time()
        while True:
            elapsed = time.time() - started
            if elapsed >= duration:
                break
            found = _count_aps_so_far(csv_path)
            print(
                f"\r[scan] {iface} 扫描中 {elapsed:4.1f}s / {duration}s  ap={found}",
                end="", file=sys.stderr, flush=True
            )
            time.sleep(1)
    finally:
        handler.terminate()
        print("\r" + " " * 56 + "\r", end="", file=sys.stderr, flush=True)

    # 结束进程后获取csv文件
    if not os.path.exists(csv_path):
        raise WifiHackingToolError(
            f"[扫描失败] airodump 没生成 csv: {csv_path}\n"
            f"  → 检查射频：读两次 /sys/class/net/{iface}/statistics/rx_packets，不涨就是网卡没在收帧",
            return_code=1,
        )

    result = parse_csv(csv_path)
    # 收尾补一句最终数量（前端能看到"扫到 7 个"）
    print(f"[scan] 完成：发现 {len(result.aps)} 个 AP，{len(result.stations)} 个客户端",
          file=sys.stderr)
    return result
    
    




