# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import sys


class Logger:
    def __init__(self, isdebug=False, isquiet=False):
        self._isdebug = isdebug
        self._isquiet = isquiet

    def info(self, msg):
        if not self._isquiet:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;34m[*]\033[0m {}".format(msg))

    def debug(self, msg):
        if not self._isquiet:
            if self._isdebug:
                msg = "\n    ".join(msg.split("\n"))
                print("\033[1;37m[*]\033[0m {}".format(msg))

    def warn(self, msg):
        if not self._isquiet:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;33m[!]\033[0m {}".format(msg))

    def error(self, msg):
        if not self._isquiet:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;31m[X]\033[0m {}".format(msg), file=sys.stderr)

    def success(self, msg):
        if not self._isquiet:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;32m[+]\033[0m {}".format(msg))

    @staticmethod
    def highlight(msg):
        return "\033[1;33m{}\033[0m".format(msg)