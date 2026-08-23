"""桌面窗口模式：pywebview 将 Web 控制台包装为原生应用窗口。

- Windows 上使用系统自带的 WebView2（Edge 内核）渲染，无浏览器界面
- 未安装 pywebview 或无图形会话时自动回退为浏览器模式
- 关闭窗口 = 停止服务，并自动恢复所有隔离中的目标
"""

import threading
import time


def _find_free_port(start=8765):
    import socket

    for p in range(start, start + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return start


def run_app(port=None, listen="loopback", token=None):
    from .audit import audit_event
    from . import server as _server
    from .server import make_server, shutdown_all

    host = "127.0.0.1" if listen == "loopback" else "0.0.0.0"
    if listen != "loopback" and not token:
        raise SystemExit("[!] 对外监听(--listen any)必须同时设置 --token")
    _server.TOKEN = token  # Handler 运行时读取模块全局 TOKEN
    port = port or _find_free_port()
    audit_event("app_start", host=host, port=port)
    _server.restore_stale_sessions()  # 断电/崩溃遗留的隔离先恢复再服务
    httpd = make_server(host, port)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/"

    try:
        import webview
    except Exception as e:
        print(f"[!] 桌面窗口不可用（{e}），回退浏览器模式。安装: pip install pywebview")
        import webbrowser

        webbrowser.open(url)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
        finally:
            shutdown_all(httpd)
        return

    print(f"[*] AegisIR 窗口已打开（http://127.0.0.1:{port}/），关闭窗口即退出")
    webview.create_window(
        "AegisIR · 应急网络隔离台", url,
        width=1280, height=840, min_size=(1000, 680),
        background_color="#0b0e14",
    )
    try:
        webview.start()  # 阻塞直到窗口关闭
    except Exception as e:
        print(f"[!] 窗口启动失败（{e}），回退浏览器模式")
        import webbrowser

        webbrowser.open(url)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    finally:
        shutdown_all(httpd)
