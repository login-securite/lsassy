import logging
import sys


class LsassyFormatter(logging.Formatter):
    # Custom formatting. Inspired by impacket "Logger" class

    def __init__(self):
        logging.Formatter.__init__(self, '%(bullet)s %(threadName)s %(message)s', None)

    def format(self, record):
        # Custom bullet formatting with colors
        if record.levelno == logging.INFO:
            record.bullet = '\033[1;34m[*]\033[0m'
        elif record.levelno == logging.DEBUG:
            record.bullet = '\033[1;37m[*]\033[0m'
        elif record.levelno == logging.WARNING:
            record.bullet = '\033[1;33m[!]\033[0m'
        elif record.levelno == logging.ERROR:
            record.bullet = '\033[1;31m[x]\033[0m'
        else:
            record.bullet = '\033[1;32m[+]\033[0m'

        # Only log stacktrace when log level is DEBUG
        if record.exc_info and logging.getLogger().getEffectiveLevel() != logging.DEBUG:
            record.exc_info = None

        return logging.Formatter.format(self, record)


def highlight(msg):
    return "\033[1;33m{}\033[0m".format(msg)


def init():
    # We add a StreamHandler and formatter to the root logger
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(LsassyFormatter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)
    logging.addLevelName(25, 'SUCCESS')
    setattr(logging, 'success', lambda message, *args: logging.getLogger()._log(25, message, args))
