# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import sys


class Logger:
    class Options:
        def __init__(self, align=1, verbosity=0, quiet=False):
            self.align = align
            self.verbosity = verbosity
            self.quiet = quiet

    def __init__(self, target="", options=Options()):
        self._target = target
        self._align = options.align
        self._verbosity = options.verbosity
        self._quiet = options.quiet

    def info(self, msg):
        if not self._quiet:
            if self._verbosity >= 1:
                msg = "\n    ".join(msg.split("\n"))
                print("\033[1;34m[*]\033[0m [{}]{}{}".format(self._target, " "*self._align, msg))

    def debug(self, msg):
        if not self._quiet:
            if self._verbosity >= 2:
                msg = "\n    ".join(msg.split("\n"))
                print("\033[1;37m[*]\033[0m [{}]{}{}".format(self._target, " "*self._align, msg))

    def warn(self, msg):
        if not self._quiet:
            if self._verbosity >= 1:
                msg = "\n    ".join(msg.split("\n"))
                print("\033[1;33m[!]\033[0m [{}]{}{}".format(self._target, " "*self._align, msg))

    def error(self, msg):
        if not self._quiet:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;31m[X]\033[0m [{}]{}{}".format(self._target, " "*self._align, msg), file=sys.stderr)

    def success(self, msg):
        if not self._quiet:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;32m[+]\033[0m [{}]{}{}".format(self._target, " "*self._align, msg))

    def raw(self, msg):
        print("{}".format(msg), end='')

    @staticmethod
    def highlight(msg):
        return "\033[1;33m{}\033[0m".format(msg)
