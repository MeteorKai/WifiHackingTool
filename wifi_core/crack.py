

from dataclasses import dataclass
import time
import os
import re
import sys
from typing import List, Optional, Tuple

from wifi_infra.errors import WifiHackingToolError
from wifi_infra.runner import OutResult, run_command

_KNOWN_HASH_EXTS = (".22000", ".cap", ".pcap", ".pcapng", ".hccapx")
_HASH_LINE_PREFIXES = ("WPA*01*", "WPA*02*")
_RC_TIMEOUT = 124
_SPEED_RE = re.compile(r"Speed\.[^:\r\n]*:\s*([0-9]+(?:\.[0-9]+)?)\s*([kMG]?)H/s")
_SPEED_MULT = {"": 1.0, "k": 1e3, "M": 1e6, "G": 1e9}


@dataclass
class CrackResults:
    hash_file: str
    wordlist: str
    elapsed: float  
    return_code: int
    message: str
    password: Optional[str] = None
    hash_count: Optional[int] = None
    speed: Optional[float] = None

    @property
    def cracked(self) -> bool:
        return bool(self.password)


def _check_hash_file(hash_file: str) -> str:
    """
    校验 hash 文件
    """
    if not hash_file or not hash_file.strip():
        raise WifiHackingToolError("hash_file 文件路径不能为空", 2)

    # 获取绝对路径
    abs_path = os.path.abspath(os.path.expanduser(hash_file))
    if not os.path.exists(abs_path):
        raise WifiHackingToolError(f"hash_file 文件不存在: {abs_path}", 2)

    if os.path.isdir(abs_path):
        raise WifiHackingToolError(f"hash_file 不能是一个目录: {abs_path}", 2)

    if os.path.getsize(abs_path) == 0:
        raise WifiHackingToolError(f"hash_file 文件为空: {abs_path}", 2)

    return abs_path


def _check_wordlist(wordlist: str) -> str:
    if not wordlist or not wordlist.strip():
        raise WifiHackingToolError("wordlist 文件路径不能为空", 2)

    abs_path = os.path.abspath(os.path.expanduser(wordlist))
    ext = os.path.splitext(abs_path)[1].lower()
    if ext in (".gz", ".zip", ".7z", ".bz2", ".xz", ".tar", ".rar", ".gzip"):
        raise WifiHackingToolError(f"wordlist 文件不支持压缩格式: {abs_path}, 请你先行解压", 2)

    if not os.path.exists(abs_path):
        raise WifiHackingToolError(f"wordlist 文件不存在: {abs_path}, Kali 现成的：/usr/share/wordlists/rockyou.txt", 2)

    if os.path.isdir(abs_path):
        raise WifiHackingToolError(f"wordlist 不能是一个目录: {abs_path}", 2)

    if os.path.getsize(abs_path) == 0:
        raise WifiHackingToolError(f"wordlist 文件为空: {abs_path}", 2)

    return abs_path

def filter_hashes_by_bssid(hashes_text: str, bssid: str) -> str:
    """
    WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID***
    WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*NONCE_AP*NONCE_CLIENT*EAPOL**MESSAGEPAIR
    """
    bssid = bssid.replace(":", "").replace("-", "").lower()
    if not bssid:
        return hashes_text or ""

    kept = []

    for line in (hashes_text or "").splitlines():
        parts = line.split("*")
        if len(parts) > 3 and parts[3].strip().lower() == bssid:
            kept.append(line)

    return ("\n".join(kept) + "\n") if kept else ""

def _looks_like_22000(hash_file: str) -> bool:
    """
    判断文件是否是 22000 格式
    """
    try:
        with open(hash_file, "r", encoding="utf-8", errors="replace") as f:
            head = f.read(8192)
    except OSError:
        return False
    return any(line.startswith(_HASH_LINE_PREFIXES) for line in head.splitlines())

def _to_22000(hash_file: str, output_dir: str, bssid: Optional[str] = None) -> str:
    """
    将 hash 文件统一转换为 .22000 格式
    deauth 的 .cap 文件需要转换为 .22000 格式才能交给 hashcat 破解
    """
    if _looks_like_22000(hash_file):
        source = hash_file
    else:
        source = os.path.join(output_dir, "converted.22000")

        # 删除上一次的产物, 否则转换失败会读到上一次的结果
        if os.path.exists(source):
            os.remove(source)

        # 转换为 .22000 格式
        from .pmkid import convert_pcapng_to_22000
        convert_pcapng_to_22000(hash_file, source)

        if not os.path.exists(source):
            raise WifiHackingToolError(f"hash_file 转换后没有得到任何 hash, 包里可能没有完整握手: {hash_file}", 2)

    if not bssid:
        return source

    # 指定了 BSSID, 则只保留指定 BSSID 的 hash
    with open(source, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
        filtered = filter_hashes_by_bssid(text, bssid)

    if not filtered:
        raise WifiHackingToolError(
            f"hash_file 中没有 BSSID 为 {bssid} 的 hash: {hash_file}"
            f"  → 先看看里面有哪些 AP: \n"
            f"      hcxhashtool -i {source} --info=stdout | grep MAC_AP",
            return_code=2
        )

    target = os.path.join(output_dir, "filtered.22000")
    with open(target, "w", encoding="utf-8", errors="replace") as f:
        f.write(filtered)

    return target

def count_hashes(text: str) -> int:
    """
    数 22000 中有几条 hash
    """
    count = 0
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith(_HASH_LINE_PREFIXES):
            continue

        if len(line.split("*")) < 9:
            continue

        count += 1
    return count

def count_hashes_without_essid(text: str) -> int:
    """
    数 22000 中没有 essid 的 hash
    """
    count = 0
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith(_HASH_LINE_PREFIXES):
            continue

        parts = line.split("*")
        if len(parts) < 9:
            continue

        if parts[5].strip() == "":
            count += 1

    return count

def build_hashcat_argv(hash_file: str, wordlist: str, outfile: str) -> List[str]:
    """
    构建 hashcat 命令行参数
    """
    return [
        "hashcat",
        "-m", "22000",
        "-a", "0", # 字典攻击
        hash_file,
        wordlist,
        "--potfile-disable",
        "-o", outfile,
        "--outfile-format", "2",
        "--status",
        "--status-timer", "10",
    ]


def _run_hashcat(hash_file: str, wordlist: str, outfile: str, log_path: str, timeout: Optional[int] = None) -> int:
    """
    运行 hashcat
    """
    argv = build_hashcat_argv(hash_file, wordlist, outfile)
    print(f"[CRACK] 启动 hashcat ...",
          file=sys.stderr)
    result = run_command(argv, timeout)

    with open(log_path, "w", encoding="utf-8", errors="replace") as f:
        f.write("$ " + " ".join(argv) + "\n\n")
        f.write(result.stdout or "")
        if result.stderr:
            f.write("\n--- stderr ---\n")
            f.write(result.stderr)

    if result.outResult == OutResult.NOTFOUND:
        raise WifiHackingToolError(f"hashcat 命令未找到, 请安装: {argv}", 3)
    elif result.outResult == OutResult.PERMISSION:
        raise WifiHackingToolError(f"hashcat 命令权限不足, 请用 root 运行: {argv}", 4)
    elif result.outResult == OutResult.ERROR:
        raise WifiHackingToolError(f"hashcat 命令执行出错: {argv}", 1)

    if result.outResult == OutResult.TIMEOUT:
        print(
            f"[CRACK] 达到超时 {timeout}s, 已中止（已破的结果保留在 {outfile}）",
            file=sys.stderr,
        )
        return _RC_TIMEOUT
    
    return result.returncode if result.returncode is not None else 1
    
def _read_cracked(outfile: str) -> Optional[str]:
    """
    读取 hashcat 破解结果
    """
    if not os.path.exists(outfile):
        return None

    with open(outfile, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            password = line.rstrip("\r\n")
            if password:
                return password

    return None

def parse_speed(log_text: str) -> Optional[float]:
    """
    hashcat 破解时的输出, 也就是日志中的内容
    Speed.#01........:    34488 H/s (58.22ms) @ Accel:1024 Loops:1024 Thr:1 Vec:16
    Speed.#*.........:    34488 H/s (...)
    """
    last: Optional[float] = None

    for line in (log_text or "").splitlines():
        m = _SPEED_RE.search(line)
        if not m:
            continue
        value, unit = m.group(1), m.group(2)
        try:
            last = float(value) * _SPEED_MULT[unit]
        except (ValueError, KeyError):
            continue

    return last



def _read_speed(log_path: str) -> Optional[float]:
    """
    读取 hashcat 破解速度
    """
    if not os.path.exists(log_path):
        return None

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            return parse_speed(f.read())
    except OSError:
        return None

def judge_crack_result(return_code: int, password: Optional[str], hash_count: int) -> Tuple[str, str]:
    """
    判断破解结果
    cracked  rc = 0 且 outfile 有结果
    exhausted  rc=1, outfile 不存在  ← ★ 这是【正常结果】，不是失败
    timeout    rc=124 且没破
    error      其它 rc 
    """
    if password:
        message = f"破解成功, 密码为: {password}"
        if return_code == _RC_TIMEOUT:
            message += "\n  ⚠ 是超时中止前破出来的, 字典没有跑完, 但是结果已出, 可正常使用"
        return ("cracked", message)

    if return_code == _RC_TIMEOUT:
        return ("timeout", "超时中止, 字典没有跑完且没有出结果. 建议不设置timeout, 或增大timeout")

    if return_code == 1:
        return ("exhausted", f"字典跑完了，{hash_count} 条 hash 都没有命中\n")

    if return_code == 0:
        return (
            "error",
            "hashcat 报告成功，但 outfile 里没有密码 —— 状态不一致\n"
            f"  → 检查 hash 文件是否有效、字典是否真的被读取",
        )

    return (
        "error",
        f"hashcat 异常退出(return_code={return_code})\n"
        f"  → 常见原因: hash 文件格式错、字典读不了、内存不足\n"
        f"  → 看日志: hashcat.log",
    )




def crack_command(
    hash_file: str,
    wordlist: str,
    bssid: Optional[str] = None,
    timeout: Optional[int] = None,
    output_dir: Optional[str] = None
) -> CrackResults:
    start_time = time.time()

    # 参数校验
    hash_file =_check_hash_file(hash_file)
    wordlist = _check_wordlist(wordlist)

    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(hash_file))

    os.makedirs(output_dir, exist_ok=True)

    # 统一成 .22000 格式, 交给 hashcat 破解
    hash_file_22000 = _to_22000(hash_file, output_dir, bssid)

    # 检查 .22000 文件格式
    with open(hash_file_22000, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    # 检查 .22000 文件中是否有有效的 hash
    hash_count = count_hashes(text)
    if hash_count == 0:
        raise WifiHackingToolError(f"hash_file 文件中没有有效的 hash: {hash_file_22000}, 可能是抓包没握手, 或是没有 PMKID", 2)

    # 检查是否存在 ESSID, 缺少 ESSID 无法爆破 hash
    no_essid = count_hashes_without_essid(text)
    if no_essid == hash_count:
        raise WifiHackingToolError(f"hash_file 文件中没有有效的 ESSID: {hash_file_22000}, PMK 的盐是 ESSID, 没有它就推导不出任何东西", 2)

    # 执行 hashcat
    outfile = os.path.join(output_dir, "crack.txt")
    log_path = os.path.join(output_dir, "hashcat.log")

    if os.path.exists(outfile):
        os.remove(outfile)

    print(f"[CRACK] {hash_count} 条 hash → {wordlist}", file=sys.stderr)
    result = _run_hashcat(hash_file_22000, wordlist, outfile, log_path, timeout)

    # 读取结果
    password = _read_cracked(outfile)
    elapsed = time.time() - start_time
    speed = _read_speed(log_path)

    _code, message = judge_crack_result(result, password, hash_count)

    return CrackResults(
        hash_file=hash_file_22000,
        wordlist=wordlist,
        elapsed=elapsed,
        return_code=result,
        message=message,
        password=password,
        hash_count=hash_count,    
        speed=speed,
    )









