
import ast
import glob
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

# 直接运行本文件时，把项目根目录加入 sys.path（否则找不到 wifi_core/wifi_infra）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_core.capture_handshake_packet import (_cap_ready, _count_eapol_lines, _list_caps,
                                      _new_cap, _probe_tshark, _tshark_healthy,
                                      check_stats, parse_handshakes, parse_packets)
from wifi_core.deauth import (DeauthRound, build_deauth_argv, decide_round, pick_station,
                    pick_station_with_wait, run_deauth_round, stop_deauth_round,
                    validate_bssid, validate_station)
from wifi_infra.errors import IfaceError, WifiHackingToolError
from wifi_infra.parse import Station, parse_csv, parse_text
from wifi_core.crack import (CrackResults, _RC_TIMEOUT, _check_hash_file, _check_wordlist,
                   _read_cracked, _read_speed, _run_hashcat, _to_22000,
                   build_hashcat_argv, count_hashes, count_hashes_without_essid,
                   filter_hashes_by_bssid, judge_crack_result, parse_speed)
from wifi_core.pmkid import (BAND_2G, BAND_5G, PmkidResults, _get_band, _summary_int,
                   build_bpf_expr, channel_to_hcxdumptool, classify_pmkid_error,
                   convert_pcapng_to_22000, parse_22000, parse_captured_count,
                   parse_hcxpcapngtool_summary)
from wifi_infra.runner import CommandResult, OutResult, run_command, start_process


_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _sample(name: str) -> str:
    """取 samples/ 下的样本（绝对路径）

    ★ 为什么不用 _sample("xxx") 这种相对路径：
      那样测试就只能在"CWD == 项目目录"时通过。
      从别的目录（比如 python -m unittest discover -s <项目>）跑会 10 个 error：
          FileNotFoundError: 'samples/airodump-scan-01.csv'
    """
    return os.path.join(_HERE, "samples", name)



class TestRunCommand(unittest.TestCase):
    def test_ok(self):
        r = run_command([sys.executable, "--version"])
        self.assertEqual(r.outResult, OutResult.OK)

    def test_nonzero(self):
        r = run_command([sys.executable, "-c", "import sys; sys.exit(7)"])
        self.assertEqual(r.outResult, OutResult.NONZERO)
        self.assertEqual(r.returncode, 7)

    def test_notfound(self):
        r = run_command(["nonexistent_command"])
        self.assertEqual(r.outResult, OutResult.NOTFOUND)

    def test_timeout(self):
        r = run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
        self.assertEqual(r.outResult, OutResult.TIMEOUT)

    @unittest.skip("Windows 上无法可靠复现权限不足")
    def test_permission(self):
        # This test may not be reliable across all platforms, so we skip it for now.
        ...

    def test_non_utf8_does_not_crash(self):
        """非 UTF-8 字节不能把工具搞崩(L-11)"""
        r = run_command([sys.executable, "-c",
                        "import sys; sys.stdout.buffer.write(b'\\xff\\xfe')"])
        self.assertIsNotNone(r.stdout)

    def test_exit_code_mapping(self):
        """退出码映射 —— 防止手滑改错一个数字"""
        cases = [(OutResult.OK, 0), (OutResult.NONZERO, 1), (OutResult.NOTFOUND, 3),
                (OutResult.TIMEOUT, 5), (OutResult.PERMISSION, 6), (OutResult.ERROR, 7)]
        for outcome, expected in cases:
            with self.subTest(outcome=outcome):          # subTest 能让 6 个值分别报错
                r = CommandResult(argv=["x"], outResult=outcome)
                self.assertEqual(r.exit_code(), expected)

    def test_report_speaks_up_on_notfound(self):
        import io, contextlib
        r = CommandResult(argv=["iw"], outResult=OutResult.NOTFOUND,
                        error="命令不存在: iw")
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            r.report()
        self.assertIn("命令不存在", buf.getvalue())


class TestParseCommand(unittest.TestCase):
    def test_real_sample_all_aps(self):
        r = parse_csv(_sample("airodump-real-01.csv"))
        self.assertEqual(len(r.aps), 8)

    def test_id_length_checksum_for_all_aps(self):
        for excel in [_sample("airodump-real-01.csv"), _sample("airodump-scan-01.csv")]:
            r = parse_csv(excel)
            for ap in r.aps:
                if ap.essid is None:
                    continue
                with self.subTest(bssid=ap.bssid):
                    self.assertEqual(len(ap.essid), ap.id_length)


    def test_trap_sample_finds_11_aps(self):
        r = parse_csv(_sample("airodump-scan-01.csv"))
        self.assertEqual(len(r.aps), 11)

        hidden = [ap for ap in r.aps if ap.essid is None]
        self.assertEqual(len(hidden), 1)


    def test_known_ssids_are_exact(self):
        """按 bssid 断言确切字节 —— 这是唯一能抓内容错误的办法"""
        got = {ap.bssid: ap.essid for ap in parse_csv(_sample("airodump-scan-01.csv")).aps}
        self.assertEqual(got["D8:47:32:1A:2B:3C"], b"TP-LINK_2.4G,5G")   # 逗号
        self.assertEqual(got["B4:0F:3B:22:33:44"], b"Cafe_WiFi_5G ")    # 尾随空格
        self.assertEqual(got["C8:3A:35:AA:BB:CC"], None)                  # 隐藏
        self.assertEqual(got["52:DD:CD:27:E7:95"], b"ZDS wifi")

    def test_ap_fields_are_parsed(self):
        """channel / power / privacy 现在一个断言都没有"""
        ap = next(a for a in parse_csv(_sample("airodump-scan-01.csv")).aps
                if a.bssid == "D8:47:32:1A:2B:3C")
        self.assertEqual(ap.channel, 6)
        self.assertEqual(ap.power, -66)
        self.assertEqual(ap.privacy, "WPA2 WPA3")

_HEADER = ("BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
           "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key")
_STA_HEADER = "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs"

def _ap_row(mac: str, id_length: int, essid_field: str, power: int = -50) -> str:
    return (f"{mac}, 2026-01-01 00:00:00, 2026-01-01 00:00:01,  6, 130, "
            f"WPA2, CCMP, PSK, {power}, 10, 0,   0.  0.  0.  0, {id_length:3d}, {essid_field}, ")


class TestGroupSsid(unittest.TestCase):
    def test_real_sample_gives_6_groups(self):
        r = parse_csv(_sample("airodump-real-01.csv"))
        self.assertEqual(len(r.group_bssid()), 6)

    def test_scan_sample_gives_9_groups(self):
        r = parse_csv(_sample("airodump-scan-01.csv"))
        self.assertEqual(len(r.group_bssid()), 9)

    def test_multi_bssid_group_is_merged(self):
        r = parse_csv(_sample("airodump-scan-01.csv"))
        groups = r.group_bssid()
        groups = {group.essid: group for group in groups}
        self.assertEqual(len(groups[b"Freedom_WiFi"].aps), 3)

    def test_hidden_aps_are_not_merged(self):
        text = (_HEADER + "\n"
                + _ap_row("AA:00:00:00:00:01", 6, "") + "\n"      # 隐藏网络 A（名字 6 字节）
                + _ap_row("AA:00:00:00:00:02", 9, "") + "\n"      # 隐藏网络 B（名字 9 字节，另一个网络）
                + _ap_row("AA:00:00:00:00:03", 6, "MyWiFi") + "\n")
        groups = parse_text(text).group_bssid()
        self.assertEqual(len(groups), 3)                          # 3 个 AP -> 3 组
        hidden = [g for g in groups if g.essid is None]
        self.assertEqual(len(hidden), 2)                          # 两个隐藏各自成组

    def test_group_order_and_best(self):
        groups = parse_csv(_sample("airodump-scan-01.csv")).group_bssid()
        self.assertEqual(groups[0].essid, b"ZDS wifi")
        self.assertEqual(groups[0].best.power, -47)
        self.assertEqual(groups[-1].essid, None)

        fw = {g.essid: g for g in groups}[b"Freedom_WiFi"]
        self.assertEqual(fw.channels, [1, 11])
        self.assertEqual(fw.best.bssid, "74:39:89:3D:C7:DC")
        self.assertEqual(fw.aps[0].power, -58)
        self.assertEqual(fw.aps[-1].power, -71)

    def test_unknown_power_sorts_last(self):
        """信号未知的 AP 不该排在真实信号前面"""
        text = (_HEADER + "\n"
                + _ap_row("AA:00:00:00:00:01", 2, "Xx", power=-1) + "\n"     # 未知
                + _ap_row("AA:00:00:00:00:02", 2, "Yy", power=-30) + "\n")   # 真实
        groups = parse_text(text).group_bssid()
        self.assertEqual(groups[0].essid, b"Yy")
        self.assertIsNone(groups[-1].best.power)

    def test_station_fields_are_parsed(self):
        """station 的 mac / power / bssid 要正确"""
        text = (_HEADER + "\n"
                + _ap_row("AA:00:00:00:00:01", 2, "Xx") + "\n"
                + "\n"                                    # ← 空行分隔两段
                + _STA_HEADER + "\n"
                + "36:20:3E:EC:C4:56, 2026-01-01 00:00:00, 2026-01-01 00:00:01, -66, 25, AA:00:00:00:00:01, \n")
        st = parse_text(text).stations[0]
        self.assertEqual(st.mac, "36:20:3E:EC:C4:56")
        self.assertEqual(st.power, -66)
        self.assertEqual(st.bssid, "AA:00:00:00:00:01")
        self.assertEqual(st.packets, 25)
    
    def test_unknown_power_becomes_none_for_station(self):
        text = (_HEADER + "\n"
                        + _ap_row("AA:00:00:00:00:01", 2, "Xx") + "\n"
                        + "\n"                                    # ← 空行分隔两段
                        + _STA_HEADER + "\n"
                        + "36:20:3E:EC:C4:56, 2026-01-01 00:00:00, 2026-01-01 00:00:01, -1, 25, AA:00:00:00:00:01, \n")
        st = parse_text(text).stations[0]
        self.assertIsNone(st.power)

    def test_unassociated_station_has_no_bssid(self):
        """(not associated) 不是 MAC，应该解析成 None"""
        text = (_HEADER + "\n" + _ap_row("AA:00:00:00:00:01", 2, "Xx") + "\n"
                + "\n" + _STA_HEADER + "\n"
                + "36:20:3E:EC:C4:56, 2026-01-01 00:00:00, 2026-01-01 00:00:01, -66, 25, (not associated) , \n")
        self.assertIsNone(parse_text(text).stations[0].bssid)

    def test_station_multiple_probed_essids(self):
        """Probed ESSIDs 是逗号列表，多个都要拿到"""
        text = (_HEADER + "\n" + _ap_row("AA:00:00:00:00:01", 2, "Xx") + "\n"
                + "\n" + _STA_HEADER + "\n"
                + "36:20:3E:EC:C4:56, 2026-01-01 00:00:00, 2026-01-01 00:00:01, -66, 25, AA:00:00:00:00:01, CMCC-8f2a, ZDS wifi\n")
        self.assertEqual(parse_text(text).stations[0].probed, [b"CMCC-8f2a", b"ZDS wifi"])


class TestStartProcess(unittest.TestCase):
    def test_start_process_ok(self):
        h = start_process([sys.executable, "-c", "import time; time.sleep(30)"])
        self.assertIsNotNone(h.proc)
        self.assertEqual(h.outResult, OutResult.OK)      # ← 抓住 outResult=None
        h.terminate()
        self.assertTrue(h.poll())

    def test_start_process_failures_survive_terminate(self):
        for argv in (["nonexistent_command_xyz"], []):
            with self.subTest(argv=argv):
                h = start_process(argv)
                self.assertIsNone(h.proc)
                h.terminate()                            # ← 不许抛异常
                self.assertTrue(h.poll())



class TestParseAircrack(unittest.TestCase):
    """从 aircrack-ng 的输出里解析出包数与握手数"""

    # 真实样本（samples/aircrack-output-01.txt）里的两组数据：
    #
    #   \x1b[0KRead 538 packets.                              ← 注意行首 ANSI 转义
    #
    #      3  48:5F:08:45:52:7A  TP-LINK_HCZZ              WPA (0 handshake)
    #   4  52:5F:08:45:52:7A                            Unknown
    #   9  86:25:19:C8:F8:D8  DIRECT-hGLaser Printer CS1831W  Unknown
    #
    # 列宽是固定对齐的（实测量过）：index 占 0-3，BSSID 占 4-22，其余从 23 开始。
    # ESSID 里可能有空格，也可能为空 —— 所以不能靠 split() 或"猜哪一段是 ESSID"。

    @classmethod
    def setUpClass(cls):
        with open(_sample("aircrack-output-01.txt"), encoding="utf-8",
                  errors="replace") as f:
            cls.text = f.read()

    # ---- 包数（parse_packets）------------------------------------------
    def test_packets_count_from_real_sample(self):
        """真实样本里写着 538 个包"""
        self.assertEqual(parse_packets(self.text), 538)

    def test_packets_count_survives_leading_ansi(self):
        """★ 'Read 538 packets.' 前面有 \\x1b[0K，而且不是第一行

        用 re.match(整段文本) 会永远匹配不上（这行不在开头），
        匹配上了拿到的也是 Match 对象而不是数字。
        """
        text = "\x1b[0KRead 12 packets.\n   1  AA:BB:CC:DD:EE:FF  X  WPA (0 handshake)"
        self.assertEqual(parse_packets(text), 12)

    def test_packets_count_missing_is_zero_not_none(self):
        """输出里没有 'Read N packets' 时该给 0，不能给 None

        None 一路传到 f-string 会打印成 "packets=None"，
        传到 int 比较会 TypeError —— 是 bug，不是"缺省"。
        """
        self.assertEqual(
            parse_packets("   1  AA:BB:CC:DD:EE:FF  X  WPA (0 handshake)"),
            0,
        )

    # ---- 握手数（parse_handshakes）-------------------------------------
    def test_handshake_count_zero(self):
        """'WPA (0 handshake)' → 0（真实样本里的 TP-LINK）"""
        self.assertEqual(parse_handshakes(self.text, "48:5F:08:45:52:7A"), 0)

    def test_handshake_found(self):
        """'WPA (1 handshake)' → 1，'WPA (2 handshake)' → 2"""
        one = "   1  AA:BB:CC:DD:EE:FF  MyNet  WPA (1 handshake)"
        two = "   2  AA:BB:CC:DD:EE:FF  MyNet  WPA (2 handshake)"
        self.assertEqual(parse_handshakes(one, "AA:BB:CC:DD:EE:FF"), 1)
        self.assertEqual(parse_handshakes(two, "AA:BB:CC:DD:EE:FF"), 2)

    def test_handshakes_are_int_not_str(self):
        """★ 必须是 int

        正则 group() 取出来的是 str；不 int() 的话
        轮询里 `if handshakes > 0` 会 TypeError，
        "抓到就提前结束"（M4 验收 #3）就永远不会生效。
        """
        self.assertIsInstance(parse_handshakes(self.text, "48:5F:08:45:52:7A"), int)

    def test_unknown_encryption_does_not_crash(self):
        """★ Unknown 分支的 group('n') 是 None，int(None) 会炸"""
        line = "   1  AA:BB:CC:DD:EE:FF  SomeNet  Unknown"
        self.assertEqual(parse_handshakes(line, "AA:BB:CC:DD:EE:FF"), 0)

    def test_essid_with_spaces(self):
        """ESSID 带空格：真实样本第 9 行 'DIRECT-hGLaser Printer CS1831W'"""
        self.assertEqual(parse_handshakes(self.text, "86:25:19:C8:F8:D8"), 0)

    def test_empty_essid(self):
        """ESSID 为空：真实样本第 4 行（BSSID 后直接是两个空格 + Unknown）"""
        self.assertEqual(parse_handshakes(self.text, "52:5F:08:45:52:7A"), 0)

    def test_bssid_not_in_table_is_zero(self):
        """表里没有这个 BSSID → 0

        这个场景每轮都会撞：--bssid 过滤下，抓包刚启动的头几秒
        aircrack-ng 的表里根本没有你的目标。
        """
        self.assertEqual(parse_handshakes(self.text, "AA:BB:CC:DD:EE:FF"), 0)

    def test_bssid_case_insensitive(self):
        """BSSID 大小写不同也要能匹配上"""
        self.assertEqual(parse_handshakes(self.text, "48:5f:08:45:52:7a"), 0)

    # ---- check_stats 的三态 --------------------------------------------
    def test_check_stats_missing_file_returns_none(self):
        """cap 还没建出来 → None（不是异常，也不是 CapStats(0,0)）"""
        self.assertIsNone(check_stats(os.path.join(tempfile.gettempdir(),
                                                "绝对不存在的.cap"), "AA:BB:CC:DD:EE:FF"))

    def test_check_stats_empty_file_returns_none(self):
        """cap 是 0 字节（刚创建）→ None"""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "cap-01.cap")
            open(p, "wb").close()
            self.assertIsNone(check_stats(p, "AA:BB:CC:DD:EE:FF"))


class TestEapolLines(unittest.TestCase):
    """tshark 字段输出的解析 —— 纯函数，不需要 tshark，也不需要网卡

    为什么把这些测试单独放在一个类里：
        parse_handshakes_tshark 里唯一有价值、也唯一可测的部分就是这段计数逻辑。
        把它抽成 _count_eapol_lines 之后，M4 里"数握手"这条路就能在 Windows 上锁死了。
    """

    BSSID = "48:5F:08:45:52:7A"
    STA = "36:20:3e:ec:c4:56"

    def test_paired_handshake(self):
        """AP→STA 和 STA→AP 各有帧 → 成对握手数 = min(两边)"""
        lines = [f"48:5f:08:45:52:7a\t{self.STA}",
                 f"{self.STA}\t48:5f:08:45:52:7a",
                 f"48:5f:08:45:52:7a\t{self.STA}",
                 f"{self.STA}\t48:5f:08:45:52:7a"]
        paired, from_ap, from_sta = _count_eapol_lines(lines, self.BSSID)
        self.assertEqual((paired, from_ap, from_sta), (2, 2, 2))

    def test_one_direction_is_not_a_handshake(self):
        """★ 只抓到一个方向 = 抓了一半，不能算成功

        算出 MIC 需要 ANonce + SNonce 两边 —— 单方向的帧在 M7 里没用。
        """
        lines = [f"48:5f:08:45:52:7a\t{self.STA}",
                 f"48:5f:08:45:52:7a\t{self.STA}"]
        paired, from_ap, from_sta = _count_eapol_lines(lines, self.BSSID)
        self.assertEqual(paired, 0)
        self.assertEqual((from_ap, from_sta), (2, 0))

    def test_ignores_tshark_noise(self):
        """★ tshark 的报错/警告行不能污染计数（真机上实测会混进来）"""
        lines = ['Running as user "root" and group "root". This could be dangerous.',
                 "Dissector bug: Invalid byte \\364 in filter name 'lCj.title'",
                 f"48:5f:08:45:52:7a\t{self.STA}",
                 f"{self.STA}\t48:5f:08:45:52:7a"]
        self.assertEqual(_count_eapol_lines(lines, self.BSSID)[0], 1)

    def test_other_bssid_is_not_counted(self):
        """别的 AP 的 EAPOL 不能算进来"""
        lines = ["aa:bb:cc:dd:ee:ff\t36:20:3e:ec:c4:56",
                 "36:20:3e:ec:c4:56\taa:bb:cc:dd:ee:ff"]
        self.assertEqual(_count_eapol_lines(lines, self.BSSID)[0], 0)

    def test_empty_lines_and_empty_fields_are_ignored(self):
        """空行 / 空 BSSID（非 wifi 帧的 EAPOL）要跳过，不能崩"""
        lines = ["", "\t", f"\t{self.STA}", f"48:5f:08:45:52:7a\t"]
        self.assertEqual(_count_eapol_lines(lines, self.BSSID)[0], 0)

    def test_returns_three_ints(self):
        """返回的必须是 int（下游要做 min() 和比较）"""
        paired, from_ap, from_sta = _count_eapol_lines([], self.BSSID)
        self.assertEqual((paired, from_ap, from_sta), (0, 0, 0))

class TestNewCap(unittest.TestCase):
    """发现"本次运行"写出的 .cap —— 快照差集版（与 capture 模块的 _list_caps/_new_cap 对应）

    背景：Kali 实测 —— 同一个 --out 连跑两次时，第 2 次曾读到上一轮的旧文件。
    """

    @staticmethod
    def _mk(path: str, n: int = 24) -> None:
        with open(path, "wb") as f:
            f.write(b"x" * n)

    def test_ignores_pre_existing_cap(self):
        """★ 上一轮的 cap 还在、新文件还没出现 → 不能误选旧的"""
        with tempfile.TemporaryDirectory() as d:
            self._mk(os.path.join(d, "cap-01.cap"), 1998)
            before = _list_caps(d)
            self.assertIsNone(_new_cap(d, before))

    def test_finds_new_cap_after_it_appears(self):
        """新文件出现后 → 选中它"""
        with tempfile.TemporaryDirectory() as d:
            self._mk(os.path.join(d, "cap-01.cap"), 1998)
            before = _list_caps(d)
            self._mk(os.path.join(d, "cap-02.cap"), 1141)
            self.assertEqual(os.path.basename(_new_cap(d, before)), "cap-02.cap")

    def test_picks_highest_number_if_several_new(self):
        """一次出现多个新文件 → 取编号最大的，保证确定性"""
        with tempfile.TemporaryDirectory() as d:
            before = _list_caps(d)
            for n in (1, 2, 3):
                self._mk(os.path.join(d, f"cap-{n:02d}.cap"))
            self.assertEqual(os.path.basename(_new_cap(d, before)), "cap-03.cap")

    def test_returns_none_when_no_cap(self):
        """还没有任何 .cap → None（不是异常）"""
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(_new_cap(d, _list_caps(d)))

    def test_ignores_other_prefixes(self):
        """别的 prefix（比如 scan-01.csv）不能被当成 .cap"""
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "scan-01.csv"), "wb").close()
            before = _list_caps(d)
            open(os.path.join(d, "scan-02.csv"), "wb").close()
            self.assertIsNone(_new_cap(d, before))

    def test_snapshot_reflects_only_cap_files(self):
        """快照只包含 .cap，且是文件名集合"""
        with tempfile.TemporaryDirectory() as d:
            self._mk(os.path.join(d, "cap-01.cap"))
            open(os.path.join(d, "cap-01.csv"), "wb").close()
            self.assertEqual(_list_caps(d), {"cap-01.cap"})


# =====================================================================
# M5：deauth（先听后踢）
# =====================================================================


class TestDeauthArgv(unittest.TestCase):
    """build_deauth_argv —— 构造 aireplay-ng 命令

    真机验证过的形态（2026-10-15，RT5370 / aircrack-ng 1.7）：
        广播: aireplay-ng --deauth 5 -a 5C:27:D4:E7:4E:46 wlan0
        单播: aireplay-ng --deauth 5 -a 5C:27:D4:E7:4E:46 -c <STA> wlan0
    """

    AP = "5c:27:d4:e7:4e:46"          # 故意用小写，测规范化
    STA = "8a:10:3f:b3:01:7a"

    def test_unicast_has_client_flag(self):
        """单播必须带 -c，且 -a 是 AP、-c 是客户端"""
        argv = build_deauth_argv("wlan0", self.AP, self.STA, 5)
        self.assertIn("-a", argv)
        self.assertIn("-c", argv)
        self.assertEqual(argv[argv.index("-a") + 1], "5C:27:D4:E7:4E:46")
        self.assertEqual(argv[argv.index("-c") + 1], "8A:10:3F:B3:01:7A")

    def test_broadcast_all_has_no_client_flag(self):
        """--station all → 广播，绝不能带 -c"""
        argv = build_deauth_argv("wlan0", self.AP, "all", 5)
        self.assertNotIn("-c", argv)
        self.assertEqual(argv[argv.index("-a") + 1], "5C:27:D4:E7:4E:46")

    def test_broadcast_none_has_no_client_flag(self):
        """station=None 也走广播（--station 没给时）"""
        argv = build_deauth_argv("wlan0", self.AP, None, 5)
        self.assertNotIn("-c", argv)

    def test_count_comes_right_after_deauth(self):
        """次数必须是 --deauth 后面那个值，而且要是字符串"""
        argv = build_deauth_argv("wlan0", self.AP, "all", 10)
        self.assertEqual(argv[1], "--deauth")
        self.assertEqual(argv[2], "10")
        self.assertIsInstance(argv[2], str)

    def test_interface_is_last(self):
        """接口名永远在最后（aireplay 的位置参数）"""
        for station in (None, "all", self.STA):
            argv = build_deauth_argv("wlan0mon", self.AP, station, 3)
            self.assertEqual(argv[-1], "wlan0mon")

    def test_first_element_is_aireplay_ng(self):
        self.assertEqual(build_deauth_argv("wlan0", self.AP, "all", 1)[0], "aireplay-ng")


class TestValidateMac(unittest.TestCase):
    """validate_bssid / validate_station —— 输入校验与退出码语义"""

    def test_valid_bssid_is_normalized(self):
        self.assertEqual(validate_bssid("5c:27:d4:e7:4e:46"), "5C:27:D4:E7:4E:46")

    def test_bad_bssid_raises_with_code_2(self):
        """★ 目标无效 = 退出码 2"""
        with self.assertRaises(WifiHackingToolError) as ctx:
            validate_bssid("不是MAC")
        self.assertEqual(ctx.exception.return_code, 2)

    def test_empty_bssid_raises(self):
        with self.assertRaises(WifiHackingToolError):
            validate_bssid("")

    def test_station_all_is_allowed(self):
        """'all' 是合法取值（广播）"""
        self.assertEqual(validate_station("all"), "all")
        self.assertEqual(validate_station("ALL"), "all")
        self.assertEqual(validate_station("  all  "), "all")

    def test_station_none_raises_with_code_2(self):
        with self.assertRaises(WifiHackingToolError) as ctx:
            validate_station(None)
        self.assertEqual(ctx.exception.return_code, 2)

    def test_bad_station_raises_with_code_2(self):
        with self.assertRaises(WifiHackingToolError) as ctx:
            validate_station("不是MAC")
        self.assertEqual(ctx.exception.return_code, 2)

    def test_validate_station_rejects_int(self):
        """★ 传 int 进来必须报可读错误，不能是 'int' object has no attribute 'strip'

        真机踩过（deauth.py 加 isinstance 守卫之前）：
        run_deauth_round 的实参顺序写错时，channel(int) 落到 station 上，
        报的就是那句莫名其妙的 AttributeError，完全定位不到。

        现在 deauth.py 里有：
            if not isinstance(mac, str):
                raise WifiHackingToolError(f"station MAC 必须是字符串，收到 {...}：{mac!r}", return_code=2)
        """
        with self.assertRaises(WifiHackingToolError) as ctx:
            validate_station(11)
        self.assertEqual(ctx.exception.return_code, 2)
        self.assertIn("必须是字符串", ctx.exception.message)


class TestPickStation(unittest.TestCase):
    """pick_station —— 从扫描结果里挑这个 AP 下的客户端（信号最强）"""

    AP = "48:5F:08:45:52:7A"
    OTHER = "88:C3:97:93:96:02"

    @staticmethod
    def _sta(mac, power, bssid, packets=1):
        return Station(mac=mac, power=power, packets=packets, bssid=bssid, probed=[])

    def test_picks_strongest_of_target_ap(self):
        stas = [self._sta("AA:AA:AA:AA:AA:01", -70, self.AP),
                self._sta("AA:AA:AA:AA:AA:02", -40, self.AP)]
        self.assertEqual(pick_station(stas, self.AP), "AA:AA:AA:AA:AA:02")

    def test_ignores_stations_of_other_aps(self):
        """★ 别的 AP 下的客户端更强，也不能选它"""
        stas = [self._sta("AA:AA:AA:AA:AA:01", -30, self.OTHER),
                self._sta("AA:AA:AA:AA:AA:02", -80, self.AP)]
        self.assertEqual(pick_station(stas, self.AP), "AA:AA:AA:AA:AA:02")

    def test_ignores_unassociated_stations(self):
        """★ bssid=None（(not associated)）的不能被选中

        真机踩过：拿一个 (not associated) 的 MAC 去 deauth，白踢了 60 秒，
        工具还报告"deauth 发出去了" —— 因为那台设备根本没连在这个 AP 上。
        """
        stas = [self._sta("AA:AA:AA:AA:AA:01", -30, None),
                self._sta("AA:AA:AA:AA:AA:02", -80, self.AP)]
        self.assertEqual(pick_station(stas, self.AP), "AA:AA:AA:AA:AA:02")

    def test_returns_none_when_no_match(self):
        stas = [self._sta("AA:AA:AA:AA:AA:01", -30, self.OTHER)]
        self.assertIsNone(pick_station(stas, self.AP))

    def test_returns_none_for_empty_list(self):
        self.assertIsNone(pick_station([], self.AP))

    def test_unknown_power_sorts_last(self):
        """power=None 的排在最后（当成 -999），不能因为它 crash"""
        stas = [self._sta("AA:AA:AA:AA:AA:01", None, self.AP),
                self._sta("AA:AA:AA:AA:AA:02", -80, self.AP)]
        self.assertEqual(pick_station(stas, self.AP), "AA:AA:AA:AA:AA:02")

    def test_bssid_case_insensitive(self):
        stas = [self._sta("AA:AA:AA:AA:AA:01", -50, "48:5f:08:45:52:7a")]
        self.assertEqual(pick_station(stas, self.AP), "AA:AA:AA:AA:AA:01")


class TestDeauthRoundObject(unittest.TestCase):
    """DeauthRound —— @dataclass 回归

    真机踩过：一开始写成裸的类级注解（没有 @dataclass / __init__），
    构造时直接 TypeError: DeauthRound() takes no arguments。
    """

    def test_is_constructible_positionally(self):
        r = DeauthRound(None, "all", ["aireplay-ng"], 1)
        self.assertIsNone(r.handler)
        self.assertEqual(r.station, "all")
        self.assertEqual(r.argv, ["aireplay-ng"])
        self.assertEqual(r.round_num, 1)

    def test_repr_does_not_crash(self):
        r = DeauthRound(None, "all", ["aireplay-ng"], 1)
        self.assertIn("DeauthRound", repr(r))


class TestStopDeauthRound(unittest.TestCase):
    """stop_deauth_round —— ★ 它是在 finally 里被调用的

    真机踩过两次：finally 里读到一个 None（某个分支没执行到赋值），
    于是整个收尾被异常带走 —— airodump-ng 留在别人的网卡上。
    finally 里调用的东西，必须对任何输入都不抛异常。
    """

    def test_tolerates_none(self):
        """★ 传 None 不许炸（第一轮都没起时就是 None）"""
        stop_deauth_round(None)          # 不抛异常即通过

    def test_tolerates_handler_none(self):
        """handler 是 None 也不许炸"""
        stop_deauth_round(DeauthRound(None, "all", [], 1))

    def test_terminates_handler(self):

        class FakeHandler:
            def __init__(self):
                self.done = False
                self.terminated = False

            def terminate(self):
                self.terminated = True

            def poll(self):
                return self.done

        h = FakeHandler()
        stop_deauth_round(DeauthRound(h, "all", [], 1))
        self.assertTrue(h.terminated)


class TestDecideRound(unittest.TestCase):
    """decide_round —— 轮询决策（纯函数）"""

    def test_stop_when_handshake_found(self):
        self.assertEqual(decide_round(1, 0.0, 5.0, 1, 60), "stop")

    def test_stop_on_timeout(self):
        self.assertEqual(decide_round(3, 0.0, 60.0, 0, 60), "stop")

    def test_wait_before_cooldown(self):
        """★ 刚踢完就再踢是浪费，也伤客户端 —— 要等冷却"""
        self.assertEqual(decide_round(1, 0.1, 5.0, 0, 60), "wait")
        self.assertEqual(decide_round(1, 9.9, 5.0, 0, 60), "wait")

    def test_deauth_again_after_cooldown(self):
        self.assertEqual(decide_round(1, 10.0, 5.0, 0, 60), "deauth-again")
        self.assertEqual(decide_round(1, 25.0, 5.0, 0, 60), "deauth-again")

    def test_handshake_beats_timeout(self):
        """即使超时了，抓到握手也是好事 —— 但要能停下"""
        self.assertEqual(decide_round(5, 0.0, 999.0, 2, 60), "stop")

    def test_always_returns_string(self):
        for args in [(1, 0.0, 0.0, 0, 60), (1, 10.0, 10.0, 0, 60), (1, 0.0, 99.0, 0, 60)]:
            self.assertIsInstance(decide_round(*args), str)

    def test_no_dead_rounds_done_zero_branch(self):
        """★ rounds_done 从 1 开始计数，所以 0 不该有特殊语义

        旧的实现里有个 `if rounds_done == 0: return "deauth-again"` 的死分支
        （capture 从 1 起数，永远走不到）。这里用 0 跑一遍，确认结果和其它轮次一致。
        """
        self.assertEqual(decide_round(0, 0.1, 5.0, 0, 60), "wait")
        self.assertEqual(decide_round(1, 0.1, 5.0, 0, 60), "wait")


class TestCapReady(unittest.TestCase):
    """_cap_ready —— "pcap 就绪"的判据

    ★ 为什么不能用 os.path.getsize(p) > 0：
      真机实测（Kali + RT5370），.cap 文件出现之后会在 0 字节上停留 ≥1.8 秒
      —— airodump 用的是带缓冲的写，pcap 头还没 flush 到磁盘。
      于是"3 秒内没有生成 .cap"这种误报，以及随后的 airodump 残留。
    """

    MAGICS = [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
              b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"]

    def _write(self, data):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "cap-01.cap")
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_accepts_all_four_pcap_magics(self):
        for m in self.MAGICS:
            with self.subTest(magic=m):
                self.assertTrue(_cap_ready(self._write(m + b"\x00" * 20)))

    def test_rejects_zero_byte_file(self):
        """★ 0 字节 = 还没就绪（这正是那个 TOCTOU 竞态）"""
        self.assertFalse(_cap_ready(self._write(b"")))

    def test_rejects_garbage(self):
        self.assertFalse(_cap_ready(self._write(b"not a pcap at all")))

    def test_rejects_short_file(self):
        """只有 2 字节，读不满 4 字节的魔数"""
        self.assertFalse(_cap_ready(self._write(b"\xd4\xc3")))

    def test_rejects_missing_file(self):
        self.assertFalse(_cap_ready(os.path.join(tempfile.gettempdir(),
                                                 "绝对不存在-12345.cap")))


class TestTsharkHealth(unittest.TestCase):
    """_tshark_healthy —— ★ tshark 不只是"存在"，还得"能正常工作"

    真机踩过（Kali 2026-10-15）：
        libwireshark-data 升到 4.6.4，而 libwireshark18 / tshark 还是 4.4.9
        → tshark 每次调用都报 "Dissector bug" 并吐协议注册表垃圾，退出码却是 0
        → 数出 0 个 EAPOL、返回 0（而不是 None）
        → 调用方永远不退回 aircrack-ng 解析
        → 明明 pcap 里有 "WPA (1 handshake)"，工具却一直报 handshakes=0
    """

    def setUp(self):
        """★ 每条测试都要重置缓存 —— _tshark_healthy 用的是模块级全局缓存

        实测踩过（写这些测试的时候）：_tshark_healthy 会把第一次探测的结果
        缓存进 _TSHARK_HEALTH，如果不重置，前一条测试留下的 False
        会让后面每条都读到 False —— 测试之间互相污染。
        """
        import wifi_core.capture_handshake_packet as _cap
        self._cap = _cap
        self._saved = getattr(_cap, "_TSHARK_HEALTH", None)
        _cap._TSHARK_HEALTH = None

    def tearDown(self):
        self._cap._TSHARK_HEALTH = self._saved

    @staticmethod
    def _fake(stdout, stderr="", returncode=0):
        return subprocess.CompletedProcess(
            args=["tshark", "--version"], returncode=returncode,
            stdout=stdout, stderr=stderr)

    # ---- 探测本身（_probe_tshark）：纯判断，不涉及缓存 ----------------
    def test_missing_binary_is_unhealthy(self):
        self.assertFalse(_probe_tshark("绝对不存在的命令-xyz-123"))

    def test_dissector_bug_output_is_unhealthy(self):
        """★ 就是真机那个 bug：能跑、退出码 0，但输出是垃圾"""
        fake = self._fake('tshark: Dissector bug: Invalid byte \\303 in filter name\n'
                          'wireshark-protocolproto_name="list"description="..."\n')
        with mock.patch.object(subprocess, "run", return_value=fake):
            self.assertFalse(_probe_tshark())

    def test_normal_version_output_is_healthy(self):
        """正常的版本串（注意大小写：TShark）要判为健康"""
        fake = self._fake('TShark (Wireshark) 4.4.9 (Git commit abc)\n')
        with mock.patch.object(subprocess, "run", return_value=fake):
            self.assertTrue(_probe_tshark())

    def test_dissector_bug_on_stderr_is_unhealthy(self):
        """Dissector bug 出现在 stderr 也要能识别"""
        fake = self._fake('', stderr='tshark: Dissector bug: Invalid byte \\200\n')
        with mock.patch.object(subprocess, "run", return_value=fake):
            self.assertFalse(_probe_tshark())

    def test_output_without_tshark_is_unhealthy(self):
        """输出的不是 tshark 的版本串 → 不可信"""
        fake = self._fake("hello world\n")
        with mock.patch.object(subprocess, "run", return_value=fake):
            self.assertFalse(_probe_tshark())

    # ---- 缓存包装（_tshark_healthy）----------------------------------
    def test_healthy_is_cached_after_first_probe(self):
        """★ 一次抓包里 tshark 的可用性不会变 —— 只探测一次

        为什么重要：check_stats 每 2 秒调一次，没缓存的话一次 60 秒抓包
        会白白 spawn 约 30 个 `tshark --version`。
        """
        self._cap._TSHARK_HEALTH = None
        call_count = {"n": 0}
        real_probe = self._cap._probe_tshark

        def counting_probe(*a, **k):
            call_count["n"] += 1
            return True

        self._cap._probe_tshark = counting_probe
        try:
            for _ in range(5):
                self.assertTrue(_tshark_healthy())
        finally:
            self._cap._probe_tshark = real_probe
        self.assertEqual(call_count["n"], 1, "探测被调用了多次 —— 缓存没生效")

    def test_cache_can_be_reset(self):
        """★ 缓存能被重置 —— 否则测试之间会互相污染

        注意不要断言"真实 tshark 是好是坏"：Windows 上它可能是好的，
        Kali 上它是坏的。测试必须和本机装没装 tshark 无关。
        """
        with mock.patch.object(self._cap, "_probe_tshark", return_value=True):
            self._cap._TSHARK_HEALTH = False     # 先塞一个旧的结论
            self.assertFalse(_tshark_healthy())  # 读到的应该是缓存（False）
            self._cap._TSHARK_HEALTH = None      # 重置
            self.assertTrue(_tshark_healthy())   # 重新探测 -> True


class TestCheckStatsTsharkFallback(unittest.TestCase):
    """check_stats 里 tshark 与 aircrack-ng 的协作

    ★ Bug B 回归（真机踩过）：
      原实现 `handshakes = parse_handshakes_tshark(...)` 直接把返回值赋回去，
      而 tshark 坏掉时它返回 None —— 于是 handshakes 变成 None，
      下游 `if handshakes > 0` 抛 TypeError:
      '>' not supported between instances of 'NoneType' and 'int'。
      None 的语义是"这条路不可用"，不是"握手数是 None"。
    """

    TABLE_0 = ("Reading packets, please wait...\n"
               "Read 16068 packets.\n"
               "\n"
               "   #  BSSID              ESSID                     Encryption\n"
               "\n"
               "   1  5C:27:D4:E7:4E:46  1-102                     WPA (0 handshake)\n")

    def setUp(self):
        self.ap = "5C:27:D4:E7:4E:46"
        d = tempfile.mkdtemp()
        self.cap = os.path.join(d, "cap-01.cap")
        with open(self.cap, "wb") as f:
            f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)

    def _run(self, table, tshark_result):
        from wifi_core.capture_handshake_packet import CapStats  # noqa: F401
        result = CommandResult(argv=["aircrack-ng"], outResult=OutResult.OK,
                               returncode=0, stdout=table)
        with mock.patch("wifi_core.capture_handshake_packet.run_command", return_value=result), \
             mock.patch("wifi_core.capture_handshake_packet.parse_handshakes_tshark",
                        return_value=tshark_result):
            return check_stats(self.cap, self.ap)

    def test_aircrack_answer_used_when_tshark_unavailable(self):
        """★ tshark 返回 None（不可用）→ 必须保留 aircrack-ng 的 0，不能变成 None"""
        stats = self._run(self.TABLE_0, None)
        self.assertIsNotNone(stats)
        self.assertIsInstance(stats.handshakes, int)
        self.assertEqual(stats.handshakes, 0)

    def test_handshakes_never_none_even_if_tshark_is_none(self):
        """★ 下游有 `if handshakes > 0` —— None 会直接 TypeError"""
        stats = self._run(self.TABLE_0, None)
        self.assertIsNotNone(stats.handshakes)
        self.assertGreaterEqual(stats.handshakes, 0)      # 这行就是会崩的那行

    def test_tshark_result_used_when_aircrack_says_zero(self):
        """aircrack-ng 表格说 0，但 tshark 数出了 2 → 用 2"""
        stats = self._run(self.TABLE_0, 2)
        self.assertEqual(stats.handshakes, 2)

    def test_aircrack_answer_wins_when_nonzero(self):
        """aircrack-ng 表格已经说 1 了 → 不需要再问 tshark"""
        table = self.TABLE_0.replace("0 handshake", "1 handshake")
        stats = self._run(table, 99)
        self.assertEqual(stats.handshakes, 1)

    def test_packets_parsed_from_same_output(self):
        self.assertEqual(self._run(self.TABLE_0, None).packets, 16068)


class TestDeauthSignature(unittest.TestCase):
    """★ 参数顺序回归 —— 同一个位置已经栽过三次

    M4:   duration 漏传
    M5:   deauth / duration 互换
    M5:   station / channel 互换（表现为 'int' object has no attribute 'strip'）

    位置传参的函数，实参顺序错了不会在写的时候报错，只在跑的时候炸 ——
    而每次"跑"都要占用网卡几十秒。这里把签名和调用点都锁住。
    """

    def test_run_deauth_round_param_order(self):
        import inspect
        params = list(inspect.signature(run_deauth_round).parameters)
        self.assertEqual(params[:6], ["iface", "bssid", "channel", "station",
                                      "count", "rounds_num"])

    def test_capture_passes_channel_before_station(self):
        """★ capture_handshake_packet 里的调用点，第 3 个实参必须是 channel"""
        path = os.path.join(_HERE, "wifi_core",
                            "capture_handshake_packet.py")
        with open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        calls = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "run_deauth_round":
                calls += 1
                names = [getattr(a, "id", None) for a in node.args]
                self.assertEqual(names[2], "channel",
                                 f"第 {node.lineno} 行：第 3 个实参应是 channel，实际 {names[2]}")
                self.assertEqual(names[3], "station",
                                 f"第 {node.lineno} 行：第 4 个实参应是 station，实际 {names[3]}")
        self.assertGreaterEqual(calls, 1, "没找到 run_deauth_round 的调用点")

    def test_build_deauth_argv_param_order(self):
        import inspect
        params = list(inspect.signature(build_deauth_argv).parameters)
        self.assertEqual(params[:4], ["iface", "bssid", "station_mac", "count"])


class TestCsvPathFollowsCapNumber(unittest.TestCase):
    """★ csv 路径必须跟着 cap 的编号走，不能硬编码 -01

    airodump-ng 用同一个编号命名同一轮的所有产物：
        cap-01.cap + cap-01.csv
        cap-02.cap + cap-02.csv     ← 复用 --out 目录时
    写死 "-01.csv" 会让你读到【上一轮】的客户端列表，
    然后拿一个早就离开的 MAC 去 deauth —— 踢了，但什么都没发生。
    """

    def test_splitext_gives_same_number(self):
        for n in ("01", "02", "17"):
            cap_path = os.path.join(tempfile.gettempdir(), "x", f"cap-{n}.cap")
            csv_path = os.path.splitext(cap_path)[0] + ".csv"
            self.assertEqual(os.path.basename(csv_path), f"cap-{n}.csv")

    def test_capture_does_not_hardcode_01_csv(self):
        """capture_handshake_packet 里不该出现写死的 '-01.csv' 字符串常量"""
        path = os.path.join(_HERE, "wifi_core",
                            "capture_handshake_packet.py")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        tree = ast.parse(src)
        bad = [n.value for n in ast.walk(tree)
               if isinstance(n, ast.Constant) and isinstance(n.value, str)
               and "-01.csv" in n.value]
        self.assertEqual(bad, [], f"写死了 csv 编号: {bad}")


class TestRaiseReturnCodes(unittest.TestCase):
    """★ 静态检查：任何 raise XxxError 都必须带 return_code

    为什么要有这条（真机踩过）：
        给 WifiHackingToolError 加了【必填】的 return_code 之后，
        全项目 16 处 raise 全部漏传 —— 于是"报错"变成"报错的报错"：
        AttributeError: 'WifiHackingToolError' object has no attribute 'return_code'
        把真正的错误信息盖住了，定位多花了一个多小时。

    给"被十几处调用的构造器"加参数时，先给默认值；再用这条兜住漏改的。
    """

    def test_all_raises_carry_return_code(self):
        here = _HERE
        bad = []
        checked = 0
        for path in sorted(glob.glob(os.path.join(here, "**", "*.py"), recursive=True)):
            if os.path.basename(path) == os.path.basename(__file__):
                continue
            try:
                with open(path, encoding="utf-8") as f:
                    tree = ast.parse(f.read())
            except (UnicodeDecodeError, SyntaxError) as e:
                self.fail(f"{os.path.basename(path)} 解析失败（会静默漏检！）: {e}")
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)):
                    continue
                name = getattr(node.exc.func, "id", None)
                if name not in ("WifiHackingToolError", "IfaceError"):
                    continue
                checked += 1
                ok = (any(k.arg == "return_code" for k in node.exc.keywords)
                      or len(node.exc.args) >= 2)
                if not ok:
                    bad.append(f"{os.path.basename(path)}:{node.lineno}")
        self.assertGreater(checked, 10, "扫描到的 raise 太少，检查逻辑可能失效了")
        self.assertEqual(bad, [], f"这些 raise 缺 return_code: {bad}")

    def test_error_classes_expose_return_code(self):
        """两个可读报错都能取到 return_code（wifitool.main 会读它）"""
        for exc in (WifiHackingToolError("x"), IfaceError("y", 4)):
            self.assertTrue(hasattr(exc, "return_code"))
            self.assertIsInstance(exc.return_code, int)

    def test_hacking_tool_error_has_default_code(self):
        """★ 不传也要能建 —— 否则漏改一处就是运行时崩溃"""
        self.assertEqual(WifiHackingToolError("x").return_code, 1)


class TestPickStationWithWait(unittest.TestCase):
    """pick_station_with_wait —— 轮询 airodump 写的 csv 找客户端

    ★ 不再自己起第二个 airodump 去扫（真机踩过）：
      capture 里 airodump 已经在跑，再起一个会和它抢同一个 monitor 接口。
      用 airodump 自己写的 csv 更准 —— 它是锁在目标信道上、--bssid 过滤过的。
    """

    AP = "48:5F:08:45:52:7A"
    STA = "AA:AA:AA:AA:AA:01"

    HEAD = ("\n"
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher,"
            " Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "\n"
            "Station MAC, First time seen, Last time seen, Power, # packets, BSSID,"
            " Probed ESSIDs\n"
            "\n")

    def _write(self, body):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "cap-01.csv")
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.HEAD + body)
        return p

    def test_finds_client(self):
        p = self._write(f"{self.STA}, 2026-01-01 00:00:00, 2026-01-01 00:00:01, -50, 10, {self.AP}, \n")
        self.assertEqual(pick_station_with_wait(p, self.AP, timeout=2.0, interval=0.1),
                         self.STA)

    def test_returns_none_on_empty_station_table(self):
        """★ 客户端安静时表是空的 → None（调用方据此报"没找到客户端"）"""
        p = self._write("")
        self.assertIsNone(pick_station_with_wait(p, self.AP, timeout=0.4, interval=0.1))

    def test_tolerates_missing_file(self):
        """★ 文件还没出现 → 等下一轮，不许崩"""
        missing = os.path.join(tempfile.gettempdir(), "绝对不存在-999.csv")
        self.assertIsNone(pick_station_with_wait(missing, self.AP,
                                                 timeout=0.4, interval=0.1))

    def test_does_not_raise_on_partial_csv(self):
        """★ airodump 每秒重写整个 csv —— 读到一半不能崩出去"""
        p = self._write(f"{self.STA}, 2026-01-01 00:00:00")     # 截断的行
        pick_station_with_wait(p, self.AP, timeout=0.4, interval=0.1)  # 不抛即通过

    def test_ignores_other_aps_clients(self):
        p = self._write("AA:AA:AA:AA:AA:09, 2026-01-01 00:00:00, 2026-01-01 00:00:01,"
                        " -30, 1, 88:C3:97:93:96:02, \n")
        self.assertIsNone(pick_station_with_wait(p, self.AP, timeout=0.4, interval=0.1))

# =====================================================================
# M6：PMKID
# =====================================================================


class TestChannelToHcxdumptool(unittest.TestCase):
    """channel_to_hcxdumptool —— hcxdumptool 的 -c 必须带频段后缀

    ★ hcxdumptool -h 原文：
        -c <digit> : set channel (1a,2a,36b,...)
                     "it is mandatory to add band information (e.g. 12a)"
      只写 '6' 它无法判断频段 -> 静默跑到错误的频率上，【不报错】。
    """

    def test_2g(self):
        for ch, want in [(1, "1a"), (6, "6a"), (11, "11a"), (14, "14a")]:
            with self.subTest(channel=ch):
                self.assertEqual(channel_to_hcxdumptool(ch), want)

    def test_5g(self):
        for ch, want in [(32, "32b"), (36, "36b"), (149, "149b"), (177, "177b")]:
            with self.subTest(channel=ch):
                self.assertEqual(channel_to_hcxdumptool(ch), want)

    def test_boundary_14_and_32(self):
        """14 是 2.4G 最后一个，32 是 5G 第一个"""
        self.assertEqual(channel_to_hcxdumptool(14), "14a")
        self.assertEqual(channel_to_hcxdumptool(32), "32b")

    def test_unjudgeable_raises_code_2(self):
        """★ 6GHz 的信道号与 2.4G/5G 重叠 —— 宁可报错，也不静默错判"""
        for bad in (0, -1, 15, 31, 178, 233, 999):
            with self.subTest(channel=bad):
                with self.assertRaises(WifiHackingToolError) as ctx:
                    channel_to_hcxdumptool(bad)
                self.assertEqual(ctx.exception.return_code, 2)

    def test_rejects_non_int(self):
        """★ 类型不对必须报可读错误，不能拼出 'Truea' / '6.0a'

        实测（修复前）：
            channel_to_hcxdumptool("6")  -> TypeError
            channel_to_hcxdumptool(None) -> TypeError
            channel_to_hcxdumptool(6.0)  -> '6.0a'   ← 静默错
            channel_to_hcxdumptool(True) -> 'Truea'  ← True 是 int 的子类
        """
        for bad in ("6", None, 6.0, True):
            with self.subTest(channel=bad):
                with self.assertRaises(WifiHackingToolError) as ctx:
                    channel_to_hcxdumptool(bad)
                self.assertEqual(ctx.exception.return_code, 2)


class TestBuildBpfExpr(unittest.TestCase):
    """build_bpf_expr —— 7.x 只剩 BPF 一条过滤路"""

    AP = "5C:27:D4:E7:4E:46"

    def test_exact_string(self):
        """★ 用 assertEqual 卡死整串，别用 assertIn

        踩过：'wlan addr3' 后面漏了空格 -> 'wlan addr35c27...'
        用 assertIn("addr3", ...) 是抓不到这个的。
        """
        self.assertEqual(build_bpf_expr(self.AP), "wlan addr3 5c27d4e74e46")

    def test_lowercase_input(self):
        self.assertEqual(build_bpf_expr("5c:27:d4:e7:4e:46"),
                         "wlan addr3 5c27d4e74e46")

    def test_has_space_before_mac(self):
        """单独再锁一次空格（这条最容易被删）"""
        self.assertTrue(build_bpf_expr(self.AP).startswith("wlan addr3 "))

    def test_bad_bssid_raises_code_2(self):
        for bad in ("", "不是MAC", None, "5C:27:D4:E7:4E"):
            with self.subTest(bssid=bad):
                with self.assertRaises(WifiHackingToolError) as ctx:
                    build_bpf_expr(bad)
                self.assertEqual(ctx.exception.return_code, 2)


class TestWriteBpf(unittest.TestCase):
    """_write_bpf —— 编译过滤器（mock 掉 run_command，Windows 上可测）"""

    AP = "5C:27:D4:E7:4E:46"

    def test_writes_compiled_code_and_uses_bpfc(self):
        import wifi_core.pmkid as pmkid
        captured = {}

        def fake_run(argv, **kw):
            captured["argv"] = argv
            return CommandResult(argv=argv, outResult=OutResult.OK,
                                 returncode=0, stdout="48 0 0 3\n100 0 0 8\n")

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "filter.bpf")
            with mock.patch.object(pmkid, "run_command", side_effect=fake_run):
                pmkid._write_bpf(path, self.AP)
            with open(path, encoding="utf-8") as f:
                self.assertIn("48 0 0 3", f.read())

        # ★ --bpfc= 必须是带等号的【单个】参数
        self.assertEqual(captured["argv"][0], "hcxdumptool")
        self.assertTrue(captured["argv"][1].startswith("--bpfc="))
        self.assertIn("addr3", captured["argv"][1])

    def test_empty_output_raises(self):
        """★ 编译失败时 stdout 为空 —— 不能默默写个空过滤器

        空过滤器 = 什么都抓不到，而且不报错 —— 会被误诊成"AP 不给 PMKID"。
        """
        import wifi_core.pmkid as pmkid
        fake = CommandResult(argv=["hcxdumptool"], outResult=OutResult.NONZERO,
                             returncode=1, stdout="", stderr="syntax error")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "filter.bpf")
            with mock.patch.object(pmkid, "run_command", return_value=fake):
                with self.assertRaises(WifiHackingToolError) as ctx:
                    pmkid._write_bpf(path, self.AP)
            self.assertEqual(ctx.exception.return_code, 1)
            self.assertFalse(os.path.exists(path), "失败时不该留下空文件")

    def test_bad_bssid_raises_before_touching_tool(self):
        import wifi_core.pmkid as pmkid
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(pmkid, "run_command") as m:
                with self.assertRaises(WifiHackingToolError):
                    pmkid._write_bpf(os.path.join(d, "f.bpf"), "不是MAC")
                m.assert_not_called()


class TestConvertPcapngTo22000(unittest.TestCase):
    """convert_pcapng_to_22000 —— ★ 必须把工具输出带回来

    返回值是 hcxpcapngtool 的 summary，classify 靠它区分三种失败原因。
    返回 hash_path 就等于把诊断信息扔了。
    """

    def _run(self, out_result, stdout="", stderr="", hash_exists=False):
        import wifi_core.pmkid as pmkid
        fake = CommandResult(argv=["hcxpcapngtool"], outResult=out_result,
                             returncode=0, stdout=stdout, stderr=stderr)
        d = tempfile.mkdtemp()
        hash_path = os.path.join(d, "x.22000")
        if hash_exists:
            with open(hash_path, "w", encoding="utf-8") as f:
                f.write("WPA*01*x\n")
        with mock.patch.object(pmkid, "run_command", return_value=fake):
            return pmkid.convert_pcapng_to_22000("/tmp/x.pcapng", hash_path)

    def test_returns_tool_output_not_path(self):
        out = self._run(OutResult.OK,
                        stdout="EAPOL M1 messages (total)................: 169\n"
                               "RSN PMKID (useless)......................: 169\n")
        self.assertIn("RSN PMKID (useless)", out)
        self.assertIn("169", out)

    def test_argv_has_all_and_o_and_input_last(self):
        import wifi_core.pmkid as pmkid
        captured = {}

        def fake(argv, **kw):
            captured["argv"] = argv
            return CommandResult(argv=argv, outResult=OutResult.OK,
                                 returncode=0, stdout="", stderr="")

        d = tempfile.mkdtemp()
        with mock.patch.object(pmkid, "run_command", side_effect=fake):
            pmkid.convert_pcapng_to_22000("/tmp/i.pcapng", os.path.join(d, "o.22000"))
        argv = captured["argv"]
        self.assertEqual(argv[0], "hcxpcapngtool")
        self.assertIn("--all", argv)          # ★ 不加它，缺 M3 时一条都不写
        self.assertEqual(argv[argv.index("-o") + 1], os.path.join(d, "o.22000"))
        self.assertEqual(argv[-1], "/tmp/i.pcapng")

    def test_missing_tool_raises_code_3(self):
        with self.assertRaises(WifiHackingToolError) as ctx:
            self._run(OutResult.NOTFOUND)
        self.assertEqual(ctx.exception.return_code, 3)

    def test_no_hashes_written_is_not_an_error(self):
        """★ 没写出 hash 是正常结果，交给 classify 解释，不能在这里抛"""
        out = self._run(OutResult.OK,
                        stdout="Information: no hashes written to hash files\n")
        self.assertIn("no hashes written", out)

    def test_real_failure_raises(self):
        with self.assertRaises(WifiHackingToolError):
            self._run(OutResult.NONZERO, stderr="cannot open", hash_exists=False)

    def test_nonzero_but_file_written_does_not_raise(self):
        """返回码非 0 但文件产出了 —— 只是 warning，别把结果扔掉"""
        out = self._run(OutResult.NONZERO, stderr="warn", hash_exists=True)
        self.assertIsInstance(out, str)


class TestParse22000(unittest.TestCase):
    """parse_22000 —— WPA*01* = PMKID，WPA*02* = EAPOL"""

    @classmethod
    def setUpClass(cls):
        with open(_sample("wpa-22000-eapol.txt"), encoding="utf-8") as f:
            cls.real = f.read()

    def test_real_sample_is_one_eapol(self):
        """真实样本 = M6 在 TP-LINK 上抓到的握手"""
        self.assertEqual(parse_22000(self.real), (0, 1))

    def test_empty_is_zero_zero(self):
        self.assertEqual(parse_22000(""), (0, 0))

    def test_counts_both_kinds_separately(self):
        """★ 不能数总行数 —— 一个文件里可能两种都有"""
        text = ("WPA*01*abc*1122*3344*0102***\n"
                "WPA*02*def*1122*3344*0102*aa*bb*cc**0\n")
        self.assertEqual(parse_22000(text), (1, 1))

    def test_missing_trailing_newline(self):
        self.assertEqual(parse_22000("WPA*01*x"), (1, 0))

    def test_ignores_unknown_kind_and_noise(self):
        text = ("summary capture file\n"
                "EAPOL M1 messages (total): 1\n"
                "WPA*03*future\n"
                "WPA*01*ok\n")
        self.assertEqual(parse_22000(text), (1, 0))


class TestParseHcxpcapngtoolSummary(unittest.TestCase):
    """parse_hcxpcapngtool_summary —— 格式坑：key 后面是一串点"""

    @classmethod
    def setUpClass(cls):
        with open(_sample("hcxpcapngtool-zero-pmkid.txt"), encoding="utf-8") as f:
            cls.zero = f.read()
        with open(_sample("hcxpcapngtool-no-pmkid.txt"), encoding="utf-8") as f:
            cls.kde = f.read()

    def test_parses_dotted_keys(self):
        s = parse_hcxpcapngtool_summary(self.zero)
        self.assertEqual(s["EAPOL M1 messages (total)"], "169")
        self.assertEqual(s["RSN PMKID (useless)"], "169")

    def test_keeps_not_detected_value(self):
        """'not detected' 要原样保留（由 _summary_int 负责转 0）"""
        s = parse_hcxpcapngtool_summary(self.zero)
        self.assertEqual(s["EAPOL ANONCE error corrections (NC)"], "not detected")

    def test_no_pmkid_sample_has_no_pmkid_key(self):
        """★ TP-LINK 的 summary 里根本没有 RSN PMKID 这一行"""
        s = parse_hcxpcapngtool_summary(self.kde)
        self.assertNotIn("RSN PMKID (useless)", s)
        self.assertEqual(s["EAPOL M1 messages (total)"], "29")

    def test_skips_information_lines(self):
        s = parse_hcxpcapngtool_summary(self.zero)
        self.assertFalse(any(k.lower().startswith("information") for k in s))

    def test_empty_and_garbage_do_not_raise(self):
        """★ 这份报告是"人读的"，格式会变 —— 只能降级，不能崩"""
        for bad in ("", "-----\n\n", "没有冒号的一行"):
            with self.subTest(text=bad):
                self.assertIsInstance(parse_hcxpcapngtool_summary(bad), dict)

    def test_key_without_dots_still_parses(self):
        s = parse_hcxpcapngtool_summary("EAPOL M1 messages: 5")
        self.assertEqual(s["EAPOL M1 messages"], "5")


class TestSummaryInt(unittest.TestCase):
    """_summary_int —— 安全取整数

    ★ 摘要里的值可能是 '169'，也可能是 'not detected'（实测存在），
      还可能是键不存在。直接 int() 会抛 ValueError —— 而这是正常情况。
    """

    def test_plain_number(self):
        self.assertEqual(_summary_int({"k": "169"}, "k"), 169)

    def test_not_detected_becomes_default(self):
        self.assertEqual(_summary_int({"k": "not detected"}, "k"), 0)

    def test_missing_key_becomes_default(self):
        self.assertEqual(_summary_int({}, "k"), 0)

    def test_custom_default(self):
        self.assertEqual(_summary_int({}, "k", default=-1), -1)

    def test_strips_whitespace(self):
        self.assertEqual(_summary_int({"k": "  42  "}, "k"), 42)


class TestParseCapturedCount(unittest.TestCase):
    """parse_captured_count —— 从 hcxdumptool 日志抠抓包数

    ★ 为什么需要：captured == 0 时，classify 里那些
      "AP 不回 M1" 的判断都没有意义 —— 得先说"你一帧都没收到"。
    """

    @classmethod
    def setUpClass(cls):
        with open(_sample("hcxdumptool-run-01.log"), encoding="utf-8") as f:
            cls.real = f.read()

    def test_real_log(self):
        self.assertEqual(parse_captured_count(self.real), 1521)

    def test_zero_packets(self):
        self.assertEqual(
            parse_captured_count("0 Packet(s) captured by kernel"), 0)

    def test_missing_returns_none(self):
        self.assertIsNone(parse_captured_count("no such line"))
        self.assertIsNone(parse_captured_count(""))


class TestClassifyPmkidError(unittest.TestCase):
    """★ M6 的核心：四种结论，每种下一步不同"""

    @classmethod
    def setUpClass(cls):
        with open(_sample("hcxpcapngtool-zero-pmkid.txt"), encoding="utf-8") as f:
            cls.zero = parse_hcxpcapngtool_summary(f.read())
        with open(_sample("hcxpcapngtool-no-pmkid.txt"), encoding="utf-8") as f:
            cls.kde = parse_hcxpcapngtool_summary(f.read())

    def test_got_pmkid(self):
        code, msg = classify_pmkid_error(2, 0, {})
        self.assertEqual(code, "ok")
        self.assertIn("2", msg)

    def test_eapol_counts_as_success_not_failure(self):
        """★ 最容易写错的一条：M6 的 pcapng 里可能同时含握手"""
        code, msg = classify_pmkid_error(0, 3, {})
        self.assertEqual(code, "ok-eapol")
        self.assertIn("3", msg)

    def test_pmkid_wins_over_eapol(self):
        self.assertEqual(classify_pmkid_error(1, 5, {})[0], "ok")

    def test_zero_pmkid_real_case(self):
        """★ 真实场景（5C:27:D4:E7:4E:46）：169 个 PMKID 全零"""
        code, msg = classify_pmkid_error(0, 0, self.zero)
        self.assertEqual(code, "zero-pmkid")
        self.assertIn("169", msg)

    def test_no_pmkid_kde_real_case(self):
        """★ 真实场景（TP-LINK_HCZZ）：回了 29 个 M1 但完全没有 PMKID 字段"""
        code, msg = classify_pmkid_error(0, 0, self.kde)
        self.assertEqual(code, "no-pmkid-kde")
        self.assertIn("29", msg)

    def test_no_m1(self):
        code, msg = classify_pmkid_error(0, 0, {})
        self.assertEqual(code, "no-m1")
        self.assertIn("rx_packets", msg)      # 必须给出体检命令

    def test_not_detected_does_not_crash(self):
        """★ int('not detected') 会抛 ValueError —— 必须被 _summary_int 兜住"""
        self.assertEqual(
            classify_pmkid_error(0, 0, {"RSN PMKID (useless)": "not detected"})[0],
            "no-m1")

    def test_always_returns_two_nonempty_strings(self):
        for args in [(1, 0, {}), (0, 1, {}), (0, 0, {}), (0, 0, self.zero)]:
            code, msg = classify_pmkid_error(*args)
            self.assertIsInstance(code, str)
            self.assertIsInstance(msg, str)
            self.assertTrue(msg)


class TestPmkidResults(unittest.TestCase):
    """PmkidResults —— 两个判据必须分开

    ★ got_pmkid  = M6 的原始目标（只认 PMKID）
      got_hash   = 有没有可爆破的东西（决定退出码）
      实测：M6 抓到 2 条 EAPOL 但 0 条 PMKID —— 这时 got_pmkid 假、got_hash 真。
    """

    def _mk(self, pmkid, eapol):
        return PmkidResults("AA:BB:CC:DD:EE:FF", 6, None, None, pmkid, eapol, "x")

    def test_got_pmkid_only_counts_pmkid(self):
        self.assertTrue(self._mk(1, 0).got_pmkid())
        self.assertFalse(self._mk(0, 3).got_pmkid())   # ★ 只有 eapol 不算

    def test_got_hash_counts_both(self):
        self.assertTrue(self._mk(1, 0).got_hash())
        self.assertTrue(self._mk(0, 3).got_hash())     # ★ eapol 也算
        self.assertFalse(self._mk(0, 0).got_hash())

    def test_counts_are_int_not_none(self):
        """计数用 0 表示"没有"，不用 None（None 会在 > 0 时 TypeError）"""
        r = self._mk(0, 0)
        self.assertIsInstance(r.pmkid_counts, int)
        self.assertIsInstance(r.eapol_counts, int)


# =====================================================================
# M7：破解
# =====================================================================


class TestCheckHashFile(unittest.TestCase):
    """_check_hash_file —— 四道关卡（空 / 不存在 / 目录 / 空文件）"""

    def test_ok_returns_abs_path(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.22000")
            with open(p, "w", encoding="utf-8") as f:
                f.write("WPA*01*x\n")
            self.assertEqual(_check_hash_file(p), os.path.abspath(p))

    def test_empty_string_raises(self):
        with self.assertRaises(WifiHackingToolError) as ctx:
            _check_hash_file("")
        self.assertEqual(ctx.exception.return_code, 2)

    def test_whitespace_only_raises(self):
        """★ "   " 不是空字符串 —— 不拦的话 abspath 会变成当前目录"""
        for bad in ("   ", "\t", "\n", " \t\n "):
            with self.subTest(path=bad):
                with self.assertRaises(WifiHackingToolError) as ctx:
                    _check_hash_file(bad)
                self.assertEqual(ctx.exception.return_code, 2)

    def test_none_raises_not_attribute_error(self):
        """★ None 不能走到 None.strip() -> AttributeError"""
        with self.assertRaises(WifiHackingToolError):
            _check_hash_file(None)

    def test_missing_raises(self):
        with self.assertRaises(WifiHackingToolError) as ctx:
            _check_hash_file("/nonexistent/xyz.22000")
        self.assertEqual(ctx.exception.return_code, 2)

    def test_directory_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(WifiHackingToolError):
                _check_hash_file(d)

    def test_empty_file_raises(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "e.22000")
            open(p, "w").close()
            with self.assertRaises(WifiHackingToolError):
                _check_hash_file(p)

    def test_txt_extension_accepted(self):
        """★ 后缀不当白名单：hashcat 看内容不看名字"""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "hash.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("WPA*01*x\n")
            self.assertEqual(_check_hash_file(p), os.path.abspath(p))


class TestCheckWordlist(unittest.TestCase):
    """_check_wordlist —— ★ 重点是 .gz 必须拦住"""

    def test_ok(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "wl.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("123456\n")
            self.assertEqual(_check_wordlist(p), os.path.abspath(p))

    def test_empty_string_raises(self):
        with self.assertRaises(WifiHackingToolError) as ctx:
            _check_wordlist("")
        self.assertEqual(ctx.exception.return_code, 2)

    def test_whitespace_only_raises(self):
        """★ 实测 bug：不拦会报"不能是一个目录" """
        for bad in ("   ", "\t", " \n "):
            with self.subTest(wordlist=bad):
                with self.assertRaises(WifiHackingToolError) as ctx:
                    _check_wordlist(bad)
                self.assertEqual(ctx.exception.return_code, 2)
                self.assertIn("不能为空", ctx.exception.message)

    def test_gz_rejected(self):
        """★ 实测：hashcat 对 .gz 不报错，只会卡死到超时"""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "rockyou.txt.gz")
            with open(p, "wb") as f:
                f.write(b"\x1f\x8b\x08\x00")
            with self.assertRaises(WifiHackingToolError) as ctx:
                _check_wordlist(p)
            self.assertEqual(ctx.exception.return_code, 2)

    def test_all_compressed_exts_rejected(self):
        for ext in (".gz", ".zip", ".7z", ".bz2", ".xz", ".tar", ".rar", ".gzip"):
            with self.subTest(ext=ext):
                with tempfile.TemporaryDirectory() as d:
                    p = os.path.join(d, "wl.txt" + ext)
                    with open(p, "wb") as f:
                        f.write(b"x")
                    with self.assertRaises(WifiHackingToolError):
                        _check_wordlist(p)

    def test_missing_raises(self):
        with self.assertRaises(WifiHackingToolError) as ctx:
            _check_wordlist("/nonexistent/wl.txt")
        self.assertEqual(ctx.exception.return_code, 2)

    def test_directory_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(WifiHackingToolError):
                _check_wordlist(d)

    def test_empty_file_raises(self):
        """★ 空字典 hashcat 也返回 rc=1，和"没破出来"无法区分"""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "empty.txt")
            open(p, "w").close()
            with self.assertRaises(WifiHackingToolError) as ctx:
                _check_wordlist(p)
            self.assertEqual(ctx.exception.return_code, 2)


class TestFilterHashesByBssid(unittest.TestCase):
    """filter_hashes_by_bssid —— MAC_AP 永远在 index 3"""

    L1 = "WPA*01*aa*112233445566*aabbccddeeff*54657374***"
    L2 = "WPA*01*bb*999999999999*aabbccddeeff*54657374***"

    def test_keeps_only_wanted(self):
        out = filter_hashes_by_bssid(self.L1 + "\n" + self.L2 + "\n", "11:22:33:44:55:66")
        self.assertIn("112233445566", out)
        self.assertNotIn("999999999999", out)

    def test_separator_insensitive(self):
        for bssid in ("11:22:33:44:55:66", "11-22-33-44-55-66", "112233445566"):
            with self.subTest(bssid=bssid):
                self.assertIn("112233445566", filter_hashes_by_bssid(self.L1, bssid))

    def test_case_insensitive(self):
        line = "WPA*01*aa*AABBCCDDEEFF*aabbccddeeff*54657374***"
        self.assertIn("AABBCCDDEEFF", filter_hashes_by_bssid(line, "aa:bb:cc:dd:ee:ff"))

    def test_no_match_returns_empty(self):
        self.assertEqual(filter_hashes_by_bssid(self.L1, "00:00:00:00:00:00"), "")

    def test_empty_bssid_returns_original(self):
        self.assertEqual(filter_hashes_by_bssid(self.L1, ""), self.L1)

    def test_short_lines_do_not_crash(self):
        self.assertEqual(filter_hashes_by_bssid("garbage\n\n*\n", "11:22:33:44:55:66"), "")


class TestCountHashes(unittest.TestCase):
    """count_hashes —— 数"能交给 hashcat"的行"""

    PMKID = "WPA*01*9ace144ac228e67f9fd01bd6dc6254d1*112233445566*aabbccddeeff*54657374***"
    EAPOL = ("WPA*02*a3568c2a9c1ba1745568c3897a3e20c9*485f0845527a*8ab1405c8f4f*"
             "54502d4c494e4b5f48435a5a*3e36eeb6*0103007502*a2")

    def test_real_sample(self):
        with open(_sample("wpa-22000-eapol.txt"), encoding="utf-8") as f:
            self.assertEqual(count_hashes(f.read()), 1)

    def test_counts_both_types(self):
        self.assertEqual(count_hashes(self.PMKID + "\n" + self.EAPOL + "\n"), 2)

    def test_duplicates_counted_separately(self):
        """★ 不去重 —— 去重是 hashcat 的事"""
        self.assertEqual(count_hashes(self.EAPOL + "\n" + self.EAPOL + "\n"), 2)

    def test_empty(self):
        self.assertEqual(count_hashes(""), 0)

    def test_ignores_noise(self):
        text = "summary capture file\nEAPOL M1 messages (total): 29\n\n" + self.EAPOL + "\n"
        self.assertEqual(count_hashes(text), 1)

    def test_ignores_too_short(self):
        """★ 字段不够的行 hashcat 也不认"""
        for bad in ("WPA*01*only3", "WPA*01*a*b*c", "WPA*02*x*y*z*w"):
            with self.subTest(line=bad):
                self.assertEqual(count_hashes(bad), 0)

    def test_ignores_unknown_type(self):
        self.assertEqual(count_hashes("WPA*03*a*b*c*d*e*f"), 0)

    def test_crlf_and_spaces(self):
        self.assertEqual(count_hashes(self.EAPOL + "\r\n"), 1)
        self.assertEqual(count_hashes("  " + self.EAPOL + "  \n"), 1)


class TestCountHashesWithoutEssid(unittest.TestCase):
    """count_hashes_without_essid —— ESSID 缺失 = 永远不可破"""

    WITH_EAPOL = "WPA*02*aa*112233445566*aabbccddeeff*54657374*anonce*snonce*eapol*0"
    NO_EAPOL = "WPA*02*aa*112233445566*aabbccddeeff**anonce*snonce*eapol*0"
    WITH_PMKID = "WPA*01*aa*112233445566*aabbccddeeff*54657374***"
    NO_PMKID = "WPA*01*aa*112233445566*aabbccddeeff****"

    def test_normal_not_counted(self):
        self.assertEqual(count_hashes_without_essid(self.WITH_EAPOL), 0)
        self.assertEqual(count_hashes_without_essid(self.WITH_PMKID), 0)

    def test_missing_essid_counted(self):
        self.assertEqual(count_hashes_without_essid(self.NO_EAPOL), 1)
        self.assertEqual(count_hashes_without_essid(self.NO_PMKID), 1)

    def test_mixed(self):
        text = self.WITH_EAPOL + "\n" + self.NO_EAPOL + "\n" + self.WITH_PMKID + "\n"
        self.assertEqual(count_hashes_without_essid(text), 1)

    def test_malformed_not_counted(self):
        """★ 格式坏 != 缺 ESSID，两者处理方式不同"""
        for bad in ("", "WPA*01*only3", "garbage"):
            with self.subTest(line=bad):
                self.assertEqual(count_hashes_without_essid(bad), 0)

    def test_real_sample_has_essid(self):
        with open(_sample("wpa-22000-eapol.txt"), encoding="utf-8") as f:
            self.assertEqual(count_hashes_without_essid(f.read()), 0)


class TestBuildHashcatArgv(unittest.TestCase):
    """build_hashcat_argv —— 参数一个都不能少"""

    def _argv(self):
        return build_hashcat_argv("/tmp/x.22000", "/tmp/wl.txt", "/tmp/out.txt")

    def test_mode_22000(self):
        argv = self._argv()
        self.assertEqual(argv[argv.index("-m") + 1], "22000")

    def test_attack_mode_dict(self):
        argv = self._argv()
        self.assertEqual(argv[argv.index("-a") + 1], "0")

    def test_potfile_disabled(self):
        """★ 不关缓存 -> 第二次跑秒出，会误判速度"""
        self.assertIn("--potfile-disable", self._argv())

    def test_outfile_format_is_2(self):
        """★ 2 = 纯密码；1 = hash:pass（密码含冒号会切错）"""
        argv = self._argv()
        self.assertEqual(argv[argv.index("--outfile-format") + 1], "2")

    def test_outfile_path(self):
        argv = self._argv()
        flag = "-o" if "-o" in argv else "--outfile"
        self.assertEqual(argv[argv.index(flag) + 1], "/tmp/out.txt")

    def test_no_quiet(self):
        """★ --quiet 会吞掉速度行，没法估算耗时"""
        self.assertNotIn("--quiet", self._argv())

    def test_hash_then_wordlist_positional(self):
        argv = self._argv()
        i = argv.index("/tmp/x.22000")
        self.assertEqual(argv[i + 1], "/tmp/wl.txt")


class TestRunHashcat(unittest.TestCase):
    """_run_hashcat —— 退出码语义 + 日志落盘"""

    def _run(self, out_result, returncode=None, timeout=None,
             stdout="", stderr="", error=None):
        import wifi_core.crack as crack
        fake = CommandResult(argv=["hashcat"], outResult=out_result,
                             returncode=returncode, stdout=stdout,
                             stderr=stderr, error=error)
        d = tempfile.mkdtemp()
        log = os.path.join(d, "hashcat.log")
        out = os.path.join(d, "crack.txt")
        with mock.patch.object(crack, "run_command", return_value=fake):
            rc = _run_hashcat("/tmp/x.22000", "/tmp/wl.txt", out, log, timeout)
        return rc, log, out

    def test_cracked_rc_0(self):
        rc, log, _ = self._run(OutResult.OK, returncode=0, stdout="PASSWORD")
        self.assertEqual(rc, 0)
        with open(log, encoding="utf-8") as f:
            self.assertIn("PASSWORD", f.read())

    def test_exhausted_rc_1(self):
        rc, _, _ = self._run(OutResult.NONZERO, returncode=1)
        self.assertEqual(rc, 1)

    def test_timeout_returns_124(self):
        """★ 超时不算失败：outfile 里可能已有结果"""
        rc, _, _ = self._run(OutResult.TIMEOUT, timeout=60)
        self.assertEqual(rc, _RC_TIMEOUT)

    def test_missing_tool_raises_code_3(self):
        with self.assertRaises(WifiHackingToolError) as ctx:
            self._run(OutResult.NOTFOUND, error="命令不存在：hashcat")
        self.assertEqual(ctx.exception.return_code, 3)

    def test_permission_raises_code_4(self):
        with self.assertRaises(WifiHackingToolError) as ctx:
            self._run(OutResult.PERMISSION, error="权限不足")
        self.assertEqual(ctx.exception.return_code, 4)

    def test_log_always_written(self):
        """★ 日志必须写：出问题时唯一线索"""
        _, log, _ = self._run(OutResult.OK, returncode=0)
        self.assertTrue(os.path.exists(log))
        with open(log, encoding="utf-8") as f:
            self.assertIn("hashcat", f.read())


class TestReadCracked(unittest.TestCase):
    """_read_cracked —— ★ 唯一判据是 outfile 有没有内容"""

    def test_missing_returns_none(self):
        """★ 实测：字典耗尽时 hashcat 根本不创建 outfile"""
        self.assertIsNone(_read_cracked("/nonexistent/cracked.txt"))

    def test_empty_file_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.txt")
            open(p, "w").close()
            self.assertIsNone(_read_cracked(p))

    def test_single_password(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.txt")
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write("wifitest123\n")
            self.assertEqual(_read_cracked(p), "wifitest123")

    def test_no_trailing_newline(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.txt")
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write("wifitest123")
            self.assertEqual(_read_cracked(p), "wifitest123")

    def test_crlf(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.txt")
            with open(p, "wb") as f:
                f.write(b"wifitest123\r\n")
            self.assertEqual(_read_cracked(p), "wifitest123")

    def test_password_with_spaces_preserved(self):
        """★ .strip() 会把密码里的空格删掉 —— 必须用 rstrip("\\r\\n")"""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.txt")
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write(" my password \n")
            self.assertEqual(_read_cracked(p), " my password ")

    def test_multiple_lines_returns_first(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.txt")
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write("pass1\npass2\n")
            self.assertEqual(_read_cracked(p), "pass1")

    def test_skips_leading_blank_lines(self):
        """★ f.readline() 在这里会返回 None —— 循环才能跳过空行"""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.txt")
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write("\n\nrealpass\n")
            self.assertEqual(_read_cracked(p), "realpass")


class TestParseSpeed(unittest.TestCase):
    """parse_speed —— 从 hashcat 输出抠 H/s"""

    REAL = "Speed.#01........:    34488 H/s (58.22ms) @ Accel:1024 Loops:1024 Thr:1 Vec:16"

    def test_real_line(self):
        self.assertAlmostEqual(parse_speed(self.REAL), 34488.0)

    def test_total_line_is_last(self):
        """★ Speed.#* 是总计，出现在最后 —— 取最后一个"""
        text = ("Speed.#1.........:   10000 H/s (1ms)\n"
                "Speed.#*.........:   20000 H/s (2ms)\n")
        self.assertAlmostEqual(parse_speed(text), 20000.0)

    def test_unit_k(self):
        self.assertAlmostEqual(parse_speed("Speed.#1.:   1.5 kH/s (1ms)"), 1500.0)

    def test_unit_m(self):
        self.assertAlmostEqual(parse_speed("Speed.#1.:   2.5 MH/s (1ms)"), 2_500_000.0)

    def test_unit_g(self):
        self.assertAlmostEqual(parse_speed("Speed.#1.:   1.2 GH/s (1ms)"), 1_200_000_000.0)

    def test_status_blocks_take_last(self):
        text = ("Speed.#01........:       0 H/s (0.00ms)\n"
                "Speed.#01........:   10000 H/s (1.00ms)\n"
                "Speed.#01........:   34488 H/s (58.22ms)\n")
        self.assertAlmostEqual(parse_speed(text), 34488.0)

    def test_no_match_returns_none(self):
        for text in ("", "nothing here", "Exhausted", None):
            with self.subTest(text=text):
                self.assertIsNone(parse_speed(text))

    def test_accel_numbers_not_confused(self):
        self.assertIsNone(parse_speed("@ Accel:1024 Loops:1024 Thr:1 Vec:16"))


class TestReadSpeed(unittest.TestCase):
    """_read_speed —— 薄壳，读不到不抛异常"""

    def test_missing_returns_none(self):
        self.assertIsNone(_read_speed("/nonexistent/hc.log"))

    def test_reads_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "hc.log")
            with open(p, "w", encoding="utf-8") as f:
                f.write("Speed.#01........:    34488 H/s (58.22ms)\n")
            self.assertAlmostEqual(_read_speed(p), 34488.0)

    def test_no_speed_line_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "hc.log")
            with open(p, "w", encoding="utf-8") as f:
                f.write("Exhausted\n")
            self.assertIsNone(_read_speed(p))


class TestJudgeCrackResult(unittest.TestCase):
    """judge_crack_result —— ★ 先看 outfile，再看 rc"""

    def test_cracked(self):
        code, msg = judge_crack_result(0, "wifitest123", 1)
        self.assertEqual(code, "cracked")
        self.assertIn("wifitest123", msg)

    def test_cracked_despite_timeout(self):
        """★ 超时前破出来的必须报成功 —— 不能吞掉结果"""
        code, msg = judge_crack_result(_RC_TIMEOUT, "wifitest123", 1)
        self.assertEqual(code, "cracked")
        self.assertIn("wifitest123", msg)

    def test_exhausted_is_rc1(self):
        """★ rc=1 是正常结果，不是失败"""
        code, msg = judge_crack_result(1, None, 2)
        self.assertEqual(code, "exhausted")
        self.assertIn("2", msg)

    def test_timeout_without_hit(self):
        self.assertEqual(judge_crack_result(_RC_TIMEOUT, None, 1)[0], "timeout")

    def test_rc0_without_password_is_error(self):
        """★ rc=0 但没密码 = 状态不一致"""
        self.assertEqual(judge_crack_result(0, None, 1)[0], "error")

    def test_other_rc_is_error(self):
        for rc in (2, 3, 4, 255):
            with self.subTest(rc=rc):
                self.assertEqual(judge_crack_result(rc, None, 1)[0], "error")

    def test_message_always_nonempty(self):
        for args in [(0, "pw", 1), (0, None, 1), (1, None, 3),
                     (_RC_TIMEOUT, "pw", 1), (_RC_TIMEOUT, None, 1), (7, None, 1)]:
            code, msg = judge_crack_result(*args)
            self.assertIsInstance(code, str)
            self.assertTrue(msg.strip())


class TestCrackResults(unittest.TestCase):
    """CrackResults —— cracked 只看 password"""

    def _mk(self, password):
        return CrackResults(hash_file="a.22000", wordlist="wl.txt",
                            elapsed=1.0, return_code=0, message="m",
                            password=password)

    def test_cracked_true(self):
        self.assertTrue(self._mk("pw").cracked)

    def test_cracked_false(self):
        self.assertFalse(self._mk(None).cracked)

    def test_cracked_false_for_empty_string(self):
        """空字符串不是"破出来了"（WPA 口令最短 8 位）"""
        self.assertFalse(self._mk("").cracked)


class TestTo22000(unittest.TestCase):
    """._to_22000 —— 统一成 22000"""

    LINE = "WPA*01*aa*112233445566*aabbccddeeff*54657374***"
    OTHER = "WPA*01*bb*999999999999*aabbccddeeff*54657374***"

    def test_passthrough_22000(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.22000")
            with open(p, "w", encoding="utf-8") as f:
                f.write(self.LINE + "\n")
            self.assertEqual(_to_22000(p, d), p)

    def test_passthrough_22000_with_bssid_filters(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.22000")
            with open(p, "w", encoding="utf-8") as f:
                f.write(self.LINE + "\n" + self.OTHER + "\n")
            out = _to_22000(p, d, bssid="11:22:33:44:55:66")
            self.assertNotEqual(out, p)
            with open(out, encoding="utf-8") as f:
                body = f.read()
            self.assertIn("112233445566", body)
            self.assertNotIn("999999999999", body)

    def test_bssid_not_found_raises(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.22000")
            with open(p, "w", encoding="utf-8") as f:
                f.write(self.LINE + "\n")
            with self.assertRaises(WifiHackingToolError) as ctx:
                _to_22000(p, d, bssid="00:00:00:00:00:00")
            self.assertEqual(ctx.exception.return_code, 2)

    def test_txt_with_22000_content_passthrough(self):
        """★ 内容是 22000 就不该去转换（哪怕后缀是 .txt）

        实测 bug：_to_22000 用【后缀】判断 ->
        .txt 走进转换分支 -> 报"找不到 hcxpcapngtool"
        """
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "hash.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write(self.LINE + "\n")
            self.assertEqual(_to_22000(p, d), p)


if __name__ == "__main__":
    unittest.main()
