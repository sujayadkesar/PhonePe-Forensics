"""PhonePe Forensics — unified entry point.

    python launch.py                 # 127.0.0.1:8750
    python launch.py 127.0.0.1:9000  # custom host:port

Opens the launcher: choose iOS or Android, parse a new extraction, or open a
case that has already been parsed by either tool.

The individual analysers still run standalone if you prefer:
    python run.py            (iOS)
    cd android && python run.py   (Android)
"""
import sys

if __name__ == "__main__":
    host_port = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:8750"
    host, _, port = host_port.partition(":")
    from launcher.app import run
    run(host=host or "127.0.0.1", port=int(port or "8750"))
