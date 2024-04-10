from PyAES.encrypt import encrypt
from PyAES.decrypt import decrypt
from getpass import getpass
import PyAES


def main():
    print("-"*85)
    print(r"""
      _       ________   ______         _______          _   __
     / \     |_   __  |.' ____ \       |_   __ \        / |_[  |
    / _ \      | |_ \_|| (___ \_| ______ | |__) |_   __`| |-'| |--.   .--.   _ .--.
   / ___ \     |  _| _  _.____`.||______||  ___/[ \ [  ]| |  | .-. |/ .'`\ \[ `.-. |
 _/ /   \ \_  _| |__/ || \____) |       _| |_    \ '/ / | |, | | | || \__. | | | | |
|____| |____||________| \______.'      |_____| [\_:  /  \__/[___]|__]'.__.' [___||__]
                                               \__.'                                 """)
    print("-"*85)
    print(f"Version: {PyAES.__version__}                                      {PyAES.__copyright__}")
    print("-"*85)
    print("""This is a simple AES (Advanced Encryption Standard) implementation in Python-3.12. It is
a pure Python implementation of AES that is designed to be used as a educational tool
only. It is not intended to be used in any other use case than educational and no
security is guaranteed for data encrypted or decrypted using this tool.""")
    print("-"*85)
    run()


def run():
    action = input("Do you want to encrypt, decrypt or quit? (e/d/q): ")
    if action == "e":
        running_mode = input("Please select cipher running mode (ECB/CBC/PCBC/CFB/OFB/CTR/GCM): ")

        if running_mode == "ECB":
            key = getpass(prompt="Please enter your key: ")
            file_path = input("Please enter path to file: ")
            confirmation = input("Are you sure you want to encrypt this file? (y/n): ")

            if confirmation == "y":
                encrypt(key, file_path, running_mode)
                print("\nEncryption complete!")

            elif confirmation == "n":
                print("Encryption aborted!")
                exit()

            else:
                print("Invalid input!")
                exit()

        elif running_mode in ["CBC", "PCBC", "CFB", "OFB", "CTR", "GCM"]:
            key = getpass(prompt="Please enter your key: ")
            iv = getpass(prompt="Please enter your iv: ")
            file_path = input("Please enter path to file: ")
            confirmation = input("Are you sure you want to encrypt this file? (y/n): ")

            if confirmation == "y":
                encrypt(key, file_path, running_mode, iv)
                print("\nEncryption complete!")

            elif confirmation == "n":
                print("Encryption aborted!")
                exit()

            else:
                print("Invalid input!")
                exit()

        else:
            print("Invalid cipher running mode")
            run()

    elif action == "d":
        running_mode = input("Please select cipher running mode (ECB/CBC/PCBC/CFB/OFB/CTR/GCM): ")

        if running_mode == "ECB":
            key = getpass(prompt="Please enter your key: ")
            file_path = input("Please enter path to file: ")
            confirmation = input("Are you sure you want to decrypt this file? (y/n): ")

            if confirmation == "y":
                decrypt(key, file_path, running_mode)
                print("\nDecryption complete!")

            elif confirmation == "n":
                print("Decryption aborted!")
                exit()

            else:
                print("Invalid input!")
                exit()

        elif running_mode in ["CBC", "PCBC", "CFB", "OFB", "CTR", "GCM"]:
            key = getpass(prompt="Please enter your key: ")
            iv = getpass(prompt="Please enter your iv: ")
            file_path = input("Please enter path to file: ")
            confirmation = input("Are you sure you want to decrypt this file? (y/n): ")

            if confirmation == "y":
                decrypt(key, file_path, running_mode, iv)
                print("\nDecryption complete!")

            elif confirmation == "n":
                print("Decryption aborted!")
                exit()

            else:
                print("Invalid input!")
                exit()

        else:
            print("Invalid cipher running mode")
            run()

    elif action == "q":
        print("Exiting...")
        exit()

    else:
        print("Invalid action (to quit enter 'q')")
        run()


if __name__ == "__main__":
    main()
