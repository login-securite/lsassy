# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

class Logger:
    def __init__(self, isdebug=False):
        self._isdebug = isdebug

    def info(self, msg):
        msg = "\n    ".join(msg.split("\n"))
        print("\033[1;34m[*]\033[0m %s" % msg)

    def debug(self, msg):
        if self._isdebug:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;37m[*]\033[0m %s" % msg)

    def warn(self, msg):
        msg = "\n    ".join(msg.split("\n"))
        print("\033[1;33m[!]\033[0m %s" % msg)

    def error(self, msg):
        msg = "\n    ".join(msg.split("\n"))
        print("\033[1;31m[X]\033[0m %s" % msg)

    def success(self, msg):
        msg = "\n    ".join(msg.split("\n"))
        print("\033[1;32m[+]\033[0m %s" % msg)

    @staticmethod
    def highlight(msg):
        return "\033[1;33m" + msg + "\033[0m"