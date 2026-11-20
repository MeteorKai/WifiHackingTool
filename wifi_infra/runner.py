#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""""
runner - 统一的外部命令执行器
"""
from dataclasses import dataclass
import signal
from typing import List, Optional
import subprocess
import sys

class OutResult:
    """
    外部命令执行结局
    """
    OK = "ok"                  # 成功（returncode == 0）
    NONZERO = "nonzero"        # 命令跑了但是返回非零退出码（returncode != 0）
    NOTFOUND = "notfound"      # 命令未找到（FileNotFoundError）
    TIMEOUT = "timeout"        # 命令执行超时（TimeoutExpired）
    PERMISSION = "permission"  # 权限不足（PermissionError）
    ERROR = "error"            # 其他错误（Exception）


def getMapping(outresult: OutResult) -> int:
    return {
        OutResult.OK: 0,
        OutResult.NONZERO: 1,
        OutResult.NOTFOUND: 3,
        OutResult.TIMEOUT: 5,
        OutResult.PERMISSION: 6,
        OutResult.ERROR: 7
    }[outresult]

@dataclass
class CommandResult:
    """
    外部命令执行完整信息
    """
    argv: List[str]
    outResult: OutResult
    returncode: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    error: Optional[str] = None # 人类可读的错误信息

    def exit_code(self) -> int:
        """返回对应的退出码"""
        return getMapping(self.outResult)

    def report(self) -> None:
        """打印执行结果"""
        if self.stdout:
            print(self.stdout, end="")
        if self.stderr:
            print(self.stderr, file=sys.stderr, end="")
        if self.error:
            print(self.error, file=sys.stderr)

def _to_text(data: Optional[bytes], encoding: str) -> Optional[str]:
    if data is None:
        return None
    else:
        return data.decode(encoding, errors="replace")



def run_command(
    argv: List[str],
    timeout: Optional[float] = None,
    encoding: str = "utf-8"
) -> CommandResult:
    """
    执行外部命令并返回结果
    """
    if not argv:
        return CommandResult(
            argv=[],
            outResult=OutResult.ERROR,
            error="命令参数为空"
        )

    try:   
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout
        )
    except FileNotFoundError:
        return CommandResult(
            argv=argv,
            outResult=OutResult.NOTFOUND,
            error=f"命令不存在：{argv[0]}"
        )

    except subprocess.TimeoutExpired:
        return CommandResult(
            argv=argv,
            outResult=OutResult.TIMEOUT,
            error=f"命令执行超时：{argv[0]}"
        )

    except PermissionError:
        return CommandResult(
            argv=argv,
            outResult=OutResult.PERMISSION,
            error=f"命令权限不足：{argv[0]}"
        )

    except Exception as e:
        return CommandResult(
            argv=argv,
            outResult=OutResult.ERROR,
            error=str(e)
        )

    out = _to_text(proc.stdout, encoding)
    err = _to_text(proc.stderr, encoding)
    ourResult = OutResult.OK if proc.returncode == 0 else OutResult.NONZERO

    return CommandResult(
        argv,
        outResult=ourResult,
        returncode=proc.returncode,
        stdout=out,
        stderr=err,
        error=None if ourResult == OutResult.OK else f"命令返回非零退出码：{proc.returncode}",
    )


@dataclass
class ProcessHandler:
    """
    常驻进程
    """
    argv: List[str]
    proc: subprocess.Popen
    outResult: OutResult
    error: Optional[str] = None

    def terminate(self) -> None:
        """终止常驻进程"""
        # 如果进程已经结束并返回值
        if self.proc is None or self.proc.poll() is not None:
            return

        try:
            self.proc.send_signal(signal.SIGINT)
        except Exception:
            pass

        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def poll(self) -> bool:
        """检查常驻进程是否结束，异常返回1，正常返回0"""
        return self.proc is None or self.proc.poll() is not None
    


def start_process(
    argv: List[str],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
) -> ProcessHandler:
    """
    常驻进程，不是一次性给出结果
    """
    if not argv:
        return ProcessHandler(
            argv=[],
            proc=None,
            outResult=OutResult.ERROR,
            error="命令参数为空"
        )

    try:
        proc = subprocess.Popen(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr
        )
    except FileNotFoundError:
        return ProcessHandler(
            argv=argv,
            proc=None,
            outResult=OutResult.NOTFOUND,
            error=f"命令不存在：{argv[0]}"
        )

    except PermissionError:
        return ProcessHandler(
            argv=argv,
            proc=None,
            outResult=OutResult.PERMISSION,
            error=f"命令权限不足：{argv[0]}"
        )
    except Exception as e:
        return ProcessHandler(
            argv=argv,
            proc=None,
            outResult=OutResult.ERROR,
            error=str(e)
        )

    return ProcessHandler(
        argv,
        proc,
        outResult=OutResult.OK,
    )


    
