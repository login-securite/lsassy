import logging


class IExec:
    """
    Interface for remote execution
    """
    debug_privilege = False

    def __init__(self, session):
        self.session = session

    def exec(self, command):
        """
        To be implemented in all exec modules
        :param command: Command to be executed on remote host
        """
        logging.info("Executing using {}".format(self.__module__))
