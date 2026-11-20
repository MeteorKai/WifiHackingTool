import platform

from .errors import IfaceError

def require_linux(command: str):
    """检查当前系统是否为Linux"""
    if platform.system() != "Linux":
        raise IfaceError(f"[平台不支持] {command} 需要 Linux 系统, 当前系统为 {platform.system()}", return_code=4)

    