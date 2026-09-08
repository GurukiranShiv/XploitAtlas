"""Portable entry point; runtime dependencies are bundled with the project."""
import sys
if sys.version_info < (3,11):
    raise SystemExit('MasterMonk requires Python 3.11 or newer.')
from server import main
if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (OSError,ValueError,RuntimeError) as exc:
        print('MasterMonk: '+str(exc),file=sys.stderr)
        raise SystemExit(1)
