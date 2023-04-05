import logging
import sys


class LsassyLogger(logging.LoggerAdapter):
    def __init__(self, disabled=False, no_color=False):
        super().__init__(self)
        self.no_color = no_color
        self.logger = logging.getLogger("lsassy")
        self.logger.setLevel(logging.INFO)
        self.logger.disabled = disabled

        formatter = LsassyFormatter(no_color).formatter
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # logging.addLevelName(25, 'SUCCESS')
        # setattr(logging, 'success', lambda message, *args: logging.getLogger()._log(25, message, args))
        # setattr(logging, 'no_color', no_color)


class LsassyFormatter(logging.Formatter):
    """
    Custom formatting. Inspired by impacket "Logger" class
    """

    def __init__(self, no_color=False):
        self.formatter = logging.Formatter.__init__(self, '%(bullet)s %(threadName)s %(message)s', None)
        self.no_color = no_color
        if self.no_color:
            self.BLUE, self.WHITE, self.YELLOW, self.RED, self.GREEN, self.NC = '', '', '', '', '', ''
        else:
            self.BLUE = '\033[1;34m'
            self.WHITE = '\033[1;37m'
            self.YELLOW = '\033[1;33m'
            self.RED = '\033[1;31m'
            self.GREEN = '\033[1;32m'
            self.NC = '\033[0m'

    def highlight(self, msg):
        """
        Highlight in yellow provided message
        :param msg: Message to highlight
        :return: Highlighted message
        """
        if self.no_color:
            return msg
        return "\033[1;33m{}\033[0m".format(msg)

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
