"""
PhonePe iOS Forensics — Entry Point
====================================
Usage:

    python run.py                    # starts on 127.0.0.1:5000
    python run.py 127.0.0.1:8000     # custom host:port

No case is pre-loaded. Use the Case Manager UI to create and process cases.
"""
import os
import sys
import webbrowser
from threading import Timer

if __name__ == "__main__":
    host_port = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:5000"

    if sys.platform == "win32":
        os.environ.setdefault("PYTHONIOENCODING", "utf-8")
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    from phonepe_forensics.webapp import app

    host, _, port = host_port.partition(":")
    port = int(port or "5000")
    url = f"http://{host or '127.0.0.1'}:{port}/"
    print(f"[*] PhonePe iOS Forensics starting at {url}")
    print(f"[*] Open the Case Manager to load evidence folders.")

    Timer(0.8, lambda: webbrowser.open(url)).start()
    app.run(host=host or "127.0.0.1", port=port, debug=False, use_reloader=False)
