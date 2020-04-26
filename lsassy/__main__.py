from lsassy.app import Lsassy
import logging

if __name__ == '__main__':
    Lsassy(level=logging.DEBUG).get_dump_file(None, None, "procdump", no_powershell=True, exec_methods=("wmi", "task"),
                                              procdump_path="C:\\Users\\rben\\Desktop\\Sysinternals\\procdump.exe")
