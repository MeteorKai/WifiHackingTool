#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wifitool - Hacking All The Wifi Networks!!!
"""

import argparse
import platform
import sys

from wifi_core.capture_handshake_packet import capture_command

from wifi_infra.errors import WifiHackingToolError
from wifi_infra.iface import IfaceError, set_managed_mode, set_monitor_mode
from wifi_core.pmkid import pmkid_command
from wifi_infra.render import render_scan
from wifi_infra.runner import run_command, OutResult, CommandResult
from wifi_core.scan import scan_command

def not_implemented(args) -> int:
    """未实现的命令处理函数。"""
    print("未实现的命令: %s" % args.cmd_name, file=sys.stderr)
    return 3



def iface_list(args) -> int:
    """iface 子命令入口：根据 command 分发。"""
    from wifi_infra.iface import iface_list_command,IfaceError
    try:
        ifaces = iface_list_command()
    except IfaceError as e:
        print(e.message, file=sys.stderr)
        return e.return_code

    if not ifaces:
        print("未找到可用的无线网卡", file=sys.stderr)
        return 0

    print(f"{'接口':<12}{'模式':<12}{'PHY'}")
    for i in ifaces:
        print(f"{i.name:<12}{i.mode:<12}{i.phy or '-'}")
    return 0


def iface_monitor_start(args) -> int:
    try:
        if set_monitor_mode(args.iface):
            print(f"[OK] {args.iface} 已成功切换至 monitor 模式")
            return 0

        return 0
    except IfaceError as e:
        print(e.message, file=sys.stderr)
        return e.return_code
    

def iface_monitor_stop(args) -> int:
    try:
        if set_managed_mode(args.iface):
            print(f"[OK] {args.iface} 已成功切换至 managed 模式")
            return 0
        
        return 0
    except IfaceError as e:
        print(e.message, file=sys.stderr)
        return e.return_code


def scan_wifi(args) -> int:
    """scan 子命令入口：根据 command 分发。"""
    try:
        result = scan_command(args.iface, args.duration if args.duration else 10)
        render_scan(result)
        return 0
    except IfaceError as e:
        print(e.message, file=sys.stderr)
        return e.return_code
    except KeyboardInterrupt:
        print("\n用户中断")
        return 0
    except WifiHackingToolError as e:
        print(e.message, file=sys.stderr)
        return e.return_code
    except Exception as e:
        print(f"发生错误: {e}", file=sys.stderr)
        return 1

def capture_packets(args) -> int:
    """capture 子命令入口"""
    try:
        result = capture_command(
            bssid=args.bssid,
            iface=args.iface,
            channel=args.channel,
            output_dir=args.output_dir,
            duration=args.duration,
            deauth=args.deauth,
            station=args.station,
            count=args.count,
        )
    except IfaceError as e:
        print(e.message, file=sys.stderr)
        return e.return_code
    except KeyboardInterrupt:
        print("\n用户中断")
        return 0
    except WifiHackingToolError as e:
        print(e.message, file=sys.stderr)
        return e.return_code
    except Exception as e:
        print(f"发生错误: {e}", file=sys.stderr)
        return 1


    if result.got_handshake:
        print(f"[结论] 抓到了握手包, handshakes = {result.handshakes}")
        print(f"  .cap 路径  : {result.cap_path}")
        return 0

    if args.deauth:
        print("\n[结论] deauth 发出去了，但没等到握手。"
              "客户端可能没重连，或启用了 PMF（802.11w）。", file=sys.stderr)
        return 1

    print("\n[结论] 没抓到握手。", file=sys.stderr)
    return 1


def pmkid_attack(args) -> int:
    """
    pmkid 命令子入口

    退出码：
        0 = 拿到 hash（PMKID 或 EAPOL）
        1 = 跑完但没拿到（最常见）
        2 = 目标无效
        3 = 缺工具（hcxdumptool / hcxpcapngtool）
        4 = 平台 / 权限
    """
    try:
        result = pmkid_command(
            bssid=args.bssid,
            iface=args.iface,
            duration=args.duration,
            channel=args.channel, 
            output_dir=args.output_dir
        )
    except IfaceError as e:
        print(e.message, file=sys.stderr)
        return e.return_code
    except KeyboardInterrupt:
        print("\n用户中断")
        return 0
    except WifiHackingToolError as e:
        print(e.message, file=sys.stderr)
        return e.return_code
    except Exception as e:
        print(f"发生错误: {e}", file=sys.stderr)
        return 1

    print(f"\n[结论] {result.message}")
    if result.hash_path:
        print(f"  hash 文件 : {result.hash_path}")
    if result.pcapng_path:
        print(f"  pcapng    : {result.pcapng_path}")

    return 0 if result.got_hash() else 1

def crack_attack(args) -> int:
    """
    crack 命令子入口, 破解之前获取的 cap 包或者 22000 文件

    退出码：
        0 = 成功
        1 = 跑完了但是字典里没有
        2 = 参数无效
        3 = 缺工具（hashcat）
        4 = 平台 / 权限
    """
    from wifi_core.crack import crack_command
    try: 
        result = crack_command(
            hash_file=args.hash_file,
            wordlist=args.wordlist,
            bssid=args.bssid,
            timeout=args.timeout,
            output_dir=args.output_dir
        )
    except IfaceError as e:
        print(e.message, file=sys.stderr)
        return e.return_code
    except KeyboardInterrupt:
        print("\n用户中断")
        return 0
    except WifiHackingToolError as e:
        print(e.message, file=sys.stderr)
        return e.return_code
    except Exception as e:
        print(f"发生错误: {e}", file=sys.stderr)
        return 1

    print(f"\n[结论] {result.message}")
    if result.cracked:
        print(f"  密码      : {result.password}")

    print(f"  hash   : {result.hash_file}（{result.hash_count} 条）")
    print(f"  字典   : {result.wordlist}")
    print(f"  耗时   : {result.elapsed:.1f} 秒")
    if result.speed:
        print(f"  速率   : {result.speed / 1000:.1f} kH/s")

    return 0 if result.cracked else 1


def web_server(args) -> int:
    """
    web 子命令入口
    启动 web 界面
    """
    try:
        from wifi_web.webapp import serve
        serve(host=args.host, port=args.port, token=args.token)
    except KeyboardInterrupt:
        print("\n用户中断")
        return 0
    except WifiHackingToolError as e:
        print(e.message, file=sys.stderr)
        return e.return_code
    except Exception as e:
        print(f"发生错误: {e}", file=sys.stderr)
        return 1

    return 0


def chaos_attack(args) -> int:
    """chaos 子命令入口"""
    try:
        from wifi_core.chaos import chaos_command
        result = chaos_command(
            bssid=args.bssid,
            iface=args.iface,
            channel=args.channel,
            station=args.station,
            duration=args.duration,
            output_dir=args.output_dir
        ) 
    except KeyboardInterrupt:
        print("\n用户中断")
        return 0
    except WifiHackingToolError as e:
        print(e.message, file=sys.stderr)
        return e.return_code
    except Exception as e:
        print(f"发生错误: {e}", file=sys.stderr)
        return 1

    print(f"\n[结论] {result.message}")
    print(f"  BSSID   : {result.bssid}")
    print(f"  客户端  : {result.station}")
    print(f"  批次数  : {result.rounds}")
    print(f"  持续    : {result.duration:.0f} 秒")
    return 0 if result.rounds > 0 else 1
    




# 解析器parser构建
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifitool",
        description="WifiHackingTool!!! Let's pwn your wifi easily!",
        epilog="示例: python wifitool.py iface list",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version="WifiHackingTool 1.0.0",
        help="显示版本信息"
    )
   # 顶层子命令
    subParsers = parser.add_subparsers(
       dest="command",
       title="可用命令",
       metavar="{iface, scan, capture, pmkid, crack, web, chaos}",
       required=True  # Python 3.7+；没写子命令则报错退出码 2
   )

    # iface子命令
    p_iface = subParsers.add_parser(
        "iface",
        help="网卡相关操作",
        description="网卡相关操作, 例如列出可用的无线网卡"
    )

    iface_subParsers = p_iface.add_subparsers(
        dest="iface_command",
        title="iface 子命令",
        metavar="{list, monitor}",
        required=True
    )

    # iface list 子命令
    p_iface_list = iface_subParsers.add_parser(
        "list",
        help="列出可用的无线网卡",
        description="列出可用的无线网卡"
    )
    p_iface_list.set_defaults(func=iface_list, cmd_name="iface list")

    # iface monitor 子命令
    p_iface_monitor = iface_subParsers.add_parser(
        "monitor",
        help="切换网卡监听模式",
        description="切换网卡监听模式"
    )

    iface_monitor_subParsers = p_iface_monitor.add_subparsers(
        dest="iface_monitor_command",
        title="iface monitor 子命令",
        metavar="{start, stop}",
        required=True
    )

    p_iface_monitor_start = iface_monitor_subParsers.add_parser(
        "start",
        help="启动 monitor 监听模式",
        description="启动 monitor 监听模式"
    )
    p_iface_monitor_start.add_argument("iface", help="网卡名称, 例如 wlan0")
    p_iface_monitor_start.set_defaults(func=iface_monitor_start, cmd_name="iface monitor start")

    p_iface_monitor_stop = iface_monitor_subParsers.add_parser(
        "stop",
        help="停止 monitor 监听模式, 切回 managed 模式",
        description="停止 monitor 监听模式, 切回 managed 模式"
    )
    p_iface_monitor_stop.add_argument("iface", help="网卡名称, 例如 wlan0")
    p_iface_monitor_stop.set_defaults(func=iface_monitor_stop, cmd_name="iface monitor stop")


    # scan 子命令
    p_scan = subParsers.add_parser(
        "scan",
        help="扫描附近的无线网络",
        description="扫描附近的无线网络"
    )
    p_scan.add_argument("iface", help="想要扫描的网卡名称, 例如 wlan0")
    p_scan.add_argument(
        "--duration",
        type=int,
        default=60,
        help="扫描时长, 单位为秒, 默认为 60 秒"
    )
    p_scan.set_defaults(func=scan_wifi, cmd_name="scan")


    # capture 子命令
    p_capture = subParsers.add_parser(
        "capture",
        help="捕获无线网络数据包",
        description="捕获无线网络数据包"
    )
    p_capture.add_argument("bssid", help="想要捕获的Wifi的BSSID")
    p_capture.add_argument("iface", help="无线网卡名称")
    p_capture.add_argument(
        "--channel",
        type=int,
        default=None,
        help="信道, 默认情况下工具自行查找"
    )
    p_capture.add_argument(
            "--duration",
            type=int,
            default=60,
            help="最长抓包秒数，默认 60s"
        )
    p_capture.add_argument(
        "--output_dir",
        default=None,
        help="捕获结果输出目录, 默认临时目录"
    )

    # 上面是纯 capture, 下面集成了 deauth 去确保拥有握手包
    p_capture.add_argument(
        "--deauth", action="store_true", help="开启 [先听后踢] 流程, 抓取握手包(默认关, 纯享capture)"
    )
    p_capture.add_argument(
        "--station", default=None, help="指定目标客户端 MAC, 'all'=广播踢所有人, 默认自动选人"
    )
    p_capture.add_argument(
        "--count", type=int, default=5, help="踢人次数, 默认5次"
    )
    
    p_capture.set_defaults(func=capture_packets, cmd_name="capture")

    # pmkid 子命令
    p_pmkid = subParsers.add_parser(
        "pmkid",
        help="PMKID攻击, 无需客户端在线",
        description="PMKID攻击, 无需客户端在线"
    )

    p_pmkid.add_argument("bssid", help="目标网络的BSSID")
    p_pmkid.add_argument("iface", help="无线网卡名称")
    p_pmkid.add_argument(
        "--channel",
        type=int,
        default=None,
        help="信道, 默认情况下工具自行查找"
    )
    p_pmkid.add_argument(
        "--duration",
        type=int,
        default=60,
        help="最长运行秒数，默认 60s"
    )
    p_pmkid.add_argument(
        "--output_dir",
        default=None,
        help="结果输出目录, 默认临时目录"
    )
    p_pmkid.set_defaults(func=pmkid_attack, cmd_name="pmkid")

    # carck爆破子命令
    p_crack = subParsers.add_parser(
        "crack",
        help="破解无线密码",
        description="破解无线密码"
    )
    p_crack.add_argument("hash_file", help="包含 PMKID 或 EAPOL 的 hash 文件路径(.cap or .22000)")
    p_crack.add_argument(
        "--wordlist", "-w",
        required=True,
        help="密码字典文件路径"
    )
    p_crack.add_argument(
        "--bssid",
        default=None,
        help="目标网络的BSSID, 只在 .cap 中有多个网络时需要(处理外来包的可选项, 本项目的 capture 本身实现了 bssid 的过滤)"
    )
    p_crack.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="最长破解时间, 单位秒, 默认不限"
    )
    p_crack.add_argument(
        "--output_dir",
        default=None,
        help="结果输出目录, 默认与 hash_file 同目录"
    )
    p_crack.set_defaults(func=crack_attack, cmd_name="crack")

    # web 界面子命令
    p_web = subParsers.add_parser(
        "web",
        help="启动 web 界面, 可在浏览器访问",
        description="kali 执行, 启动 web 界面, 可在本机浏览器访问"
    )
    p_web.add_argument(
        "--host",
        default="127.0.0.1",
        help="web 界面监听地址, 默认 127.0.0.1, 局域网访问可设置为 0.0.0.0"
    )
    p_web.add_argument(
        "--port",
        type=int,
        default=8080,
        help="web 界面监听端口, 默认 8080"
    )
    p_web.add_argument(
        "--token",
        default=None,
        help="web 界面访问 token, 默认随机生成"
    )
    p_web.set_defaults(func=web_server, cmd_name="web")

    # 菜单 chaos 子命令
    p_chaos = subParsers.add_parser(
        "chaos",
        help="对某个在线客户端进行断网攻击",
        description="对某个在线客户端进行断网攻击"
    )
    p_chaos.add_argument("bssid")
    p_chaos.add_argument("iface")
    p_chaos.add_argument("--channel", type=int, required=True, help="必须显式给, deauth 要锁信道")
    p_chaos.add_argument("--station", default="all", help="目标客户端 MAC, 默认 all=踢所有人")
    p_chaos.add_argument("--duration", type=int, default=300, help="持续秒数, 默认 300")
    p_chaos.add_argument("--output_dir", default=None)

    p_chaos.set_defaults(func=chaos_attack, cmd_name="chaos")


    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # 没有func，说明是空壳实现
    if not hasattr(args, "func"):
        return not_implemented(args)

    return args.func(args)
        
    

if __name__ == "__main__":
    sys.exit(main())
