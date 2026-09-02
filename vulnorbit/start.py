"""Run with Python 3.11 or newer; no third-party runtime dependencies."""
import sys
if sys.version_info < (3, 11):
    raise SystemExit("XploitAtlas requires Python 3.11 or newer. Python 3.12 is recommended.")
from server import main
if __name__ == "__main__":
    raise SystemExit(main())
