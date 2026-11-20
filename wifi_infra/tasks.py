"""
任务管理
"""


import contextlib
from dataclasses import dataclass, field
from datetime import datetime
import io
import threading
from typing import Any, Callable, Dict, List, Optional
import uuid

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"

MAX_PROGRESS_LINES = 200

def _now() -> str:
    """
    当前时间
    """
    return datetime.now().astimezone().isoformat(timespec="seconds")

class TaskBusy(Exception):
    """已有任务在跑 —— 网卡只有一张，不能并行抓包"""

@dataclass
class Task:
    id: str
    cmd: str                                # scan / capture / pmkid / crack......
    status: str = STATUS_PENDING
    created_at: str = field(default_factory=_now)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    progress: List[str] = field(default_factory=list)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    return_code: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        给 JSON 用的视图
        """
        return {
            "id": self.id,
            "cmd": self.cmd,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "params": self.params,
            "progress": list(self.progress),
            "result": self.result,
            "error": self.error,
            "return_code": self.return_code,
        }


class _TasksLog(io.TextIOBase):
    """
    线程安全的任务日志流对象
    """
    def __init__(self, task: Task, lock: threading.Lock, max_lines: int = MAX_PROGRESS_LINES):
        self._task = task
        self._lock = lock
        self._max_lines = max_lines
        self._buf = ""

    def writable(self) -> bool:
        return True

    def write(self, s: str) -> int:
        """
        写入日志
        """
        if not s:
            return 0
        with self._lock:
            self._buf += s

            while True:
                idxs = [i for i in (self._buf.find("\n"), self._buf.find("\r")) if i >= 0]
                if not idxs:
                    break
                idx = min(idxs)
                line = self._buf[:idx].strip()
                self._buf = self._buf[idx + 1:]
                if line:
                    self._task.progress.append(line)
                    if len(self._task.progress) > self._max_lines:
                        del self._task.progress[: len(self._task.progress) - self._max_lines]

        return len(s)

    def flush(self) -> None:
        """
        刷新
        """
        with self._lock:
            line = self._buf.strip()
            self._buf = ""
            if line:
                self._task.progress.append(line)



class TaskManager:
    """
    任务管理器, 单任务串行
    """
    def __init__(self, max_progress_lines: int = MAX_PROGRESS_LINES):
        self._lock = threading.Lock()
        self._tasks: Dict[str, Task] = {}
        self._running: Optional[str] = None
        self._max_progress_lines = max_progress_lines

    # 查询
    def busy(self) -> bool:
        """
        是否有任务在运行
        """
        with self._lock:
            return self._running is not None
    
    def get(self, task_id: str) -> Optional[Task]:
        """
        获取任务
        """
        with self._lock:
            return self._tasks.get(task_id)

    def list_tasks(self, limit: int = 50) -> List[Task]:
        """列举任务, 新的在前"""
        with self._lock:
            items = list(self._tasks.values())
        return items[-limit:][::-1]

    # 提交
    def submit(self, cmd: str, func: Callable[[], Dict[str, Any]], params: Optional[Dict[str, Any]] = None) -> Task:
        """
        提交任务
        """
        with self._lock:
            if self._running is not None:
                raise TaskBusy(f"已有任务在跑（{self._running}），等它结束再试")
            task = Task(id=uuid.uuid4().hex[:12], cmd=cmd, params=params or {})
            self._tasks[task.id] = task
            self._running = task.id

        threading.Thread(
            target=self._run_task,
            args=(task, func),
            daemon=True,
            name=f"task-{task.id}"
        ).start()

        return task


    def _run_task(self, task: Task, func: Callable[[], Dict[str, Any]]) -> None:
        with self._lock:
            task.status = STATUS_RUNNING
            task.started_at = _now()

        log = _TasksLog(task, self._lock, self._max_progress_lines)
        try:
            with contextlib.redirect_stderr(log):
                result = func()

            with self._lock:
                task.result = result
                task.status = STATUS_DONE
                task.return_code = 0
        except Exception as e:
            # 取出 WifiHackingToolError 中的 message and return_code
            message = getattr(e, "message", None) or str(e)
            return_code = getattr(e, "return_code", None)
            with self._lock:
                task.error = message
                task.return_code = return_code if return_code is not None else 1
                task.status = STATUS_FAILED
        finally:
            log.flush()
            log.close()
            with self._lock:
                task.finished_at = _now()
                if self._running == task.id:
                    self._running = None

            


    

        












    