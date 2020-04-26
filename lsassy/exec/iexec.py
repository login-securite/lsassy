import logging


class IExec:
    debug_privilege = False

    def __init__(self, session):
        self.session = session

    def exec(self, command):
        logging.info("Executing using {}".format(self.__module__))
