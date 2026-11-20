"""
web 界面
kali 跑 flask 服务
"""

import secrets
import sys
from wifi_infra import adapters
from typing import Optional

from flask import Flask, jsonify, redirect, request, url_for

from wifi_infra.errors import WifiHackingToolError
from wifi_infra.tasks import TaskBusy, TaskManager

_TOKEN = None

app = Flask(__name__)
_mgr = TaskManager()


def _check_token() -> bool:
    if _TOKEN is None:
        return True

    return request.headers.get("X-Token") == _TOKEN

def _guard():
    if not _check_token():
        return jsonify({"error": "token 无效或缺失"}), 401
    return None

def _submit(cmd: str, func, **params):
    """提交任务并返回 202 相应"""
    try:
        task = _mgr.submit(cmd, func, params)
    except TaskBusy as e:
        return jsonify({"error": str(e)}), 409

    return jsonify({"task_id": task.id, "status": task.status}), 202


@app.route("/")
def index():
    return redirect(url_for("static", filename="index.html"))

@app.route("/health")
def health():
    return jsonify({"ok": True, "service": "wifitool web"})




def serve(host: str, port: int, token: Optional[str]) -> None:
    global _TOKEN

    if token is None and host not in ("127.0.0.1", "localhost"):
        token = secrets.token_urlsafe(16)

    _TOKEN = token

    print(f"[web]监听: http://{host}:{port}/", file=sys.stderr)
    if token:
        print(f"[web]   访问令牌: {token}", file=sys.stderr)
    else:
        print(f"[web]   访问令牌: 无", file=sys.stderr)

    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


@app.route("/api/iface_list")
def api_iface_list():
    bad = _guard()
    if bad:
        return bad

    try:
        return jsonify(adapters.run_iface_list())
    except WifiHackingToolError as e:
        return jsonify({"error": e.message}), e.return_code


@app.route("/api/iface_mode", methods=["POST"])
def api_iface_mode():
    """改变网卡模式"""
    bad = _guard()
    if bad:
        return bad

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "请求体必须是 JSON 对象"}), 400

    iface = body.get("iface", "wlan0")
    if not isinstance(iface, str) or not iface.strip() or iface.lstrip().startswith("-"):
        return jsonify({"error": "请输入有效的网卡接口名"}), 400
    iface = iface.strip()

    mode = body.get("mode")
    if mode not in ("monitor", "managed"):
        return jsonify({"error": "需要 mode 为(monitor / managed)"}), 400

    if _mgr.busy():
        return jsonify({"error": "有任务正在运行"}), 409
    try:
        return jsonify(adapters.run_iface_mode(iface, mode))
    except WifiHackingToolError as e:
        return jsonify({"error": e.message}), e.return_code



@app.route("/api/scan", methods=["POST"])
def api_scan():
    bad = _guard()
    if bad:
        return bad

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "请求体必须是 JSON 对象"}), 400

    iface = body.get("iface", "wlan0")
    if not isinstance(iface, str) or not iface.strip() or iface.lstrip().startswith("-"):
        return jsonify({"error": "请输入有效的网卡接口名"}), 400
    iface = iface.strip()

    duration = body.get("duration", 10)
    if type(duration) is not int or not 1 <= duration <= 120:
        return jsonify({"error": "扫描时长必须是 1–120 的整数"}), 400

    return _submit("scan", lambda: adapters.run_scan(iface, duration), iface=iface, duration=duration)


@app.route("/api/capture", methods=["POST"])
def api_capture():
    bad = _guard()
    if bad:
        return bad
    body = request.get_json(silent=True) or {}
    bssid = body.get("bssid")
    if not bssid:
        return jsonify({"error": "缺少 bssid 参数"}), 400
    
    iface = body.get("iface") or "wlan0"
    channel = body.get("channel")
    duration = int(body.get("duration", 60))
    poll_interval = float(body.get("poll_interval", 2.0))
    deauth = bool(body.get("deauth", False))
    station = body.get("station")
    count = int(body.get("count", 5))

    return _submit(
        "capture",
        lambda: adapters.run_capture(bssid=bssid, iface=iface, channel=channel, duration=duration, poll_interval=poll_interval, deauth=deauth, station=station, count=count),
        bssid=bssid, iface=iface, channel=channel, duration=duration, poll_interval=poll_interval, deauth=deauth, station=station, count=count
    )
    

@app.route("/api/pmkid", methods=["POST"])
def api_pmkid():
    bad = _guard()
    if bad:
        return bad
    body = request.get_json(silent=True) or {}
    bssid = body.get("bssid")
    if not bssid:
        return jsonify({"error": "缺少 bssid 参数"}), 400

    iface = body.get("iface") or "wlan0"
    channel = body.get("channel")
    duration = int(body.get("duration", 60))

    return _submit(
        "pmkid",
        lambda: adapters.run_pmkid(bssid=bssid, iface=iface, duration=duration, channel=channel),
        bssid=bssid, iface=iface, channel=channel, duration=duration
    )

@app.route("/api/crack", methods=["POST"])
def api_crack():
    bad = _guard()
    if bad:
        return bad
    body = request.get_json(silent=True) or {}
    hash_file = body.get("hash_file")
    wordlist = body.get("wordlist")
    if not hash_file or not wordlist:
        return jsonify({"error": "缺少 hash_file 或 wordlist 参数"}), 400

    bssid = body.get("bssid")
    timeout = body.get("timeout")
    if timeout is not None:
        timeout = int(timeout)

    return _submit(
        "crack",
        lambda: adapters.run_crack(hash_file=hash_file, wordlist=wordlist, bssid=bssid, timeout=timeout),
        hash_file=hash_file, wordlist=wordlist, bssid=bssid, timeout=timeout
    )

@app.route("/api/chaos", methods=["POST"])
def api_chaos():
    """
    无限 deauth, 断网攻击
    """
    bad = _guard()
    if bad:
        return bad

    body = request.get_json(silent=True) or {}
    bssid = body.get("bssid")
    if not bssid:
        return jsonify({"error": "缺少 bssid"}), 400

    channel = body.get("channel")
    if channel is None:
        return jsonify({"error": "缺少 channel（chaos 必须锁信道）"}), 400

    iface = body.get("iface") or "wlan0"
    station = body.get("station") or "all"
    duration = int(body.get("duration", 300))

    return _submit(
        "chaos",
        lambda: adapters.run_chaos(bssid, iface, int(channel), station, duration),
        bssid=bssid, iface=iface, channel=channel,
        station=station, duration=duration,
    )


# 查询类接口
@app.route("/api/task/<task_id>")
def api_task(task_id: str):
    bad = _guard()
    if bad:
        return bad
    task = _mgr.get(task_id)
    if task is None:
        return jsonify({"error": "任务不存在"}), 404
    return jsonify(task.to_dict())


@app.route("/api/tasks")
def api_tasks():
    bad = _guard()
    if bad:
        return bad
    return jsonify({"tasks": [task.to_dict() for task in _mgr.list_tasks()]})

@app.route("/api/state")
def api_state():
    bad = _guard()
    if bad:
        return bad
    return jsonify({"busy": _mgr.busy(), "tasks": [task.to_dict() for task in _mgr.list_tasks(limit=10)]})