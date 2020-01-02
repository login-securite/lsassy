# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import sys


class Logger:
    def __init__(self, is_debug=False, is_quiet=False):
        self._is_debug = is_debug
        self._is_quiet = is_quiet

    def info(self, msg):
        if not self._is_quiet:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;34m[*]\033[0m {}".format(msg))

    def debug(self, msg):
        if not self._is_quiet:
            if self._is_debug:
                msg = "\n    ".join(msg.split("\n"))
                print("\033[1;37m[*]\033[0m {}".format(msg))

    def warn(self, msg):
        if not self._is_quiet:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;33m[!]\033[0m {}".format(msg))

    def error(self, msg):
        if not self._is_quiet:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;31m[X]\033[0m {}".format(msg), file=sys.stderr)

    def success(self, msg, force=False):
        if not self._is_quiet or force:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;32m[+]\033[0m {}".format(msg))

    @staticmethod
    def highlight(msg):
        return "\033[1;33m{}\033[0m".format(msg)