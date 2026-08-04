from interface.user_interface import UserInterface
from os import name , geteuid 
def check_root():

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

        exit(1)


def main():
    check_root()
    ui = UserInterface()

    ui.start()


if __name__ == "__main__":
    main()