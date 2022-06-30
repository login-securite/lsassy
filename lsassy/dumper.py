import logging
import importlib
import pkgutil

from lsassy import dumpmethod, exec


class Dumper:
    """
    Loader class to handle dump methods.

    This class looks for provided dump module name in `dumpmethod` package and returns an instance of this dump method.
    Returns None if doesn't exist.
    """
    def __init__(self, session, timeout, time_between_commands):

        self._session = session
        self._timeout = timeout
        self._time_between_commands = time_between_commands

    def load(self, dump_module):
        """
        Load provided dump module
        :param dump_module: class name of dump module in dumpmethod package
        :return: instance of dump module
        """
        try:
            return importlib.import_module("lsassy.dumpmethod.{}".format(dump_module.lower()), "DumpMethod").DumpMethod(self._session, self._timeout, self._time_between_commands)
        except ModuleNotFoundError:
            logging.warning("Dump module '{}' doesn't exist".format(dump_module))
            return None
        except Exception:
            logging.warning("Unknown error while loading '{}'".format(dump_module), exc_info=True)
            return None

    @staticmethod
    def list_dump_methods():
        return [name for _, name, _ in pkgutil.iter_modules(dumpmethod.__path__)]

    @staticmethod
    def list_exec_methods():
        return [name for _, name, _ in pkgutil.iter_modules(exec.__path__)]
