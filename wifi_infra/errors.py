

class IfaceError(Exception):
    """网卡领域的可读报错"""
    def __init__(self, message: str, return_code: int):
        super().__init__(message)
        self.message = message
        self.return_code = return_code


class WifiHackingToolError(Exception):
    """wifi hacking tool领域的可读报错

    return_code 的语义：
        1 = 一般失败（进程起不来 / 文件没生成 / 未知错误）
        2 = 目标无效（没找到 AP / 没找到客户端 / MAC 格式错）
        3 = 缺工具（iw / airodump-ng / aireplay-ng / aircrack-ng 不在）
        4 = 平台或权限（非 Linux / 权限不足）
    """
    def __init__(self, message: str, return_code: int = 1):
        super().__init__(message)
        self.message = message
        self.return_code = return_code
