import logging
import importlib
import os


class Dumper:
    """
    Loader class to handle dump methods.

    This class looks for provided dump module name in `dumpmethod` package and returns an instance of this dump method.
    Returns None if doesn't exist.
    """
    def __init__(self, session, timeout):

        self._session = session
        self._timeout = timeout

    def load(self, dump_module):
        """
        Load provided dump module
        :param dump_module: class name of dump module in dumpmethod package
        :return: instance of dump module
        """
        try:
            return importlib.import_module("lsassy.dumpmethod.{}".format(dump_module.lower()), "DumpMethod").DumpMethod(self._session, self._timeout)
        except ModuleNotFoundError:
            logging.warning("Dump module '{}' doesn't exist".format(dump_module))
            return None
        except Exception:
            logging.warning("Unknown error while loading '{}'".format(dump_module), exc_info=True)
            return None

    @staticmethod
    def list():
        return [
            "comsvcs",
            "comsvcs_stealth",
            "procdump",
            "dumpert",
            "dumpertdll",
            "mirrordump",
        ]
