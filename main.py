import sys
from os import name, geteuid

from interface.user_interface import UserInterface


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        if name != "nt" and geteuid() != 0:
            print("""
========================================
        EYE Network Vision
========================================

Permission Error:

Root privileges are required
for network packet capture.

Please run:

sudo python3 main.py

========================================
            """)
            sys.exit(1)
        ui = UserInterface()
        ui.start()
    else:
        from interface.pyqt_interface import run_gui
        run_gui()


if __name__ == "__main__":
    main()