import logging
import sys


class LsassyLogger(logging.LoggerAdapter):
    def __init__(self, no_color=False):
        super().__init__(self, extra=None)
        self.logger = logging.getLogger("lsassy")
        self.logger.propagate = False
        self.no_color = no_color

        formatter = LsassyFormatter(no_color=no_color)
        self.handler = logging.StreamHandler(sys.stdout)
        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)

    def lsassy_highlight(self, msg):
        """
        Highlight in yellow provided message
        :param msg: Message to lsassy_highlight
        :return: Highlighted message
        """
        if self.no_color:
            return msg
        return "\033[1;33m{}\033[0m".format(msg)

    def set_no_color(self, no_color=False):
        self.logger.removeHandler(self.handler)
        self.handler = logging.StreamHandler(sys.stdout)
        self.handler.setFormatter(LsassyFormatter(no_color=no_color))
        self.logger.addHandler(self.handler)


class LsassyFormatter(logging.Formatter):
    """
    Custom formatting. Inspired by impacket "Logger" class
    """
    def __init__(self, no_color=False):
        self.formatter = logging.Formatter.__init__(self, '%(bullet)s %(threadName)s %(message)s', None)
        self.no_color = no_color
        self.BLUE, self.WHITE, self.YELLOW, self.RED, self.GREEN, self.NC = '', '', '', '', '', ''
        if not self.no_color:
            self.BLUE = '\033[1;34m'
            self.WHITE = '\033[1;37m'
            self.YELLOW = '\033[1;33m'
            self.RED = '\033[1;31m'
            self.GREEN = '\033[1;32m'
            self.NC = '\033[0m'

    def format(self, record):
        """
        Custom bullet formatting with colors
        :param record: Record to log
        """
        if record.levelno == logging.INFO:
            record.bullet = '{}[*]{}'.format(self.BLUE, self.NC)
        elif record.levelno == logging.DEBUG:
            record.bullet = '{}[*]{}'.format(self.WHITE, self.NC)
        elif record.levelno == logging.WARNING:
            record.bullet = '{}[!]{}'.format(self.YELLOW, self.NC)
        elif record.levelno == logging.ERROR:
            record.bullet = '{}[x]{}'.format(self.RED, self.NC)
        else:
            record.bullet = '{}[+]{}'.format(self.GREEN, self.NC)

        # Only log stacktrace when log level is DEBUG
        if record.exc_info and logging.getLogger("lsassy").getEffectiveLevel() != logging.DEBUG:
            record.exc_info = None

        return logging.Formatter.format(self, record)


lsassy_logger = LsassyLogger()
