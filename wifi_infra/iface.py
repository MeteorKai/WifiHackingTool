"""
无线网卡管理: 查询模式, 切换为monitor模式, 切换为managed模式
"""


from dataclasses import dataclass
import platform
import re
import sys
from typing import List, Optional

from .errors import IfaceError
from .runner import CommandResult, OutResult, run_command
from .utils import require_linux


@dataclass
class IfaceInfo:
    """网卡信息"""
    name: str
    mode: str
    phy: Optional[str] = None



def parse_iw_dev_output(output: str) -> List[IfaceInfo]:
    """
    解析 iw dev 命令的输出
    形如：
    phy#0
        Interface wlan0
                ifindex 10
                wdev 0x1
                addr 56:f2:b6:b7:30:dd
                type managed
    """
    parsed_result: List[IfaceInfo] = []
    cur_phy: Optional[str] = None
    cur_name: Optional[str] = None
    cur_mode: Optional[str] = None

    for line in output.splitlines():
        line = line.strip()
        m = re.match(r"phy#(\d+)", line)
        if m:
            cur_phy = m.group(1)
            continue
        m = re.match(r"Interface (\S+)", line)
        if m:
            cur_name = m.group(1)
            continue
        m = re.match(r"type (\S+)", line)
        if m:
            cur_mode = m.group(1)
            parsed_result.append(IfaceInfo(name=cur_name, mode=cur_mode, phy=cur_phy))
            continue

    return parsed_result


def _check_result(result: CommandResult, command: str) -> None:
    if result.outResult == OutResult.NOTFOUND:
        raise IfaceError(f"[命令未找到] {command} 依赖的命令不存在", return_code=result.exit_code())
    elif result.outResult == OutResult.PERMISSION:
        raise IfaceError("[权限不足] 请确认是否以管理员权限运行", return_code=result.exit_code())
    elif result.outResult == OutResult.TIMEOUT:
        raise IfaceError(f"[命令执行超时] {command} 命令执行超时", return_code=result.exit_code())
    elif result.outResult != OutResult.OK:
        raise IfaceError(f"[未知错误] 执行命令失败, 错误信息: {result.error or result.stderr}", return_code=result.exit_code())


def iface_list_command() -> List[IfaceInfo]:
    """使用 iw 命令列出可用的无线网卡"""
    require_linux("iface list")
    result = run_command(
        ['iw', 'dev'],
        timeout=10
    )

    _check_result(result, "iw dev")

    return parse_iw_dev_output(result.stdout)


def get_iface_by_name(name: str) -> IfaceInfo:
    ifaces = iface_list_command()
    for iface in ifaces:
        if iface.name == name:
            return iface
    else:
        return None

def set_monitor_mode(iface_name: str) -> bool:
    """
    原始命令:
    ip link set wlan0 down
    iw dev wlan0 set type monitor
    ip link set wlan0 up
    """
    return _set_iface_mode(iface_name, "monitor")


def set_managed_mode(iface_name: str) -> bool:
    """
    原始命令:
    ip link set wlan0 down
    iw dev wlan0 set type managed
    ip link set wlan0 up
    """
    return _set_iface_mode(iface_name, "managed")


def _set_iface_mode(iface_name: str, target_mode: str) -> bool:
    """
    设置网卡模式
    """
    require_linux("ip")

    # 检查网卡是否存在
    iface = get_iface_by_name(iface_name)
    if not iface:
        raise IfaceError(f"[网卡不存在] 未找到网卡 {iface_name}", return_code=1)

    # 检查网卡当前模式
    if iface.mode == target_mode:
        print(f"[模式已匹配] 网卡 {iface.name} 当前模式为 {iface.mode}, 无需切换", file=sys.stderr)
        return False
    else:
        result = run_command(
            ["ip", "link", "set", iface.name, "down"],
            timeout=5
        )
        _check_result(result, "ip link set down")

        result = run_command(
            ["iw", "dev", iface.name, "set", "type", target_mode],
            timeout=5
        )
        _check_result(result, "iw dev set type")

        result = run_command(
            ["ip", "link", "set", iface.name, "up"],
            timeout=5
        )
        if result.outResult != OutResult.OK:
            print(f"[警告] 执行 ip link set up 失败, 但模式转换成功! 错误信息: {result.error or result.stderr}", file=sys.stderr)

        # 回头再检查一次
        iface = get_iface_by_name(iface_name)
        if iface.mode != target_mode:
            raise IfaceError(f"[模式设置失败] 网卡 {iface.name} 设置模式 {target_mode} 失败", return_code=1)

        return True

        

def require_monitor_mode(iface: str) -> None:
    """扫之前确认网卡在 monitor 模式"""
    result = run_command(
        ['iw', 'dev', iface, 'info'],
        timeout=5
    )
    if "type monitor" not in (result.stdout or ""):
        raise IfaceError(f"[模式错误] 网卡 {iface} 当前模式不是 monitor, 先跑 iface monitor start 吧", return_code=1)
