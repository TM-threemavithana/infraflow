"""
InfraFlow CLI Package Executable Entry Point.

Enables package execution via:
    python3 -m infraflow <command> [options]
"""

import sys
from infraflow.cli import main

if __name__ == "__main__":
    sys.exit(main())
