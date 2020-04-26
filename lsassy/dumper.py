import logging
import importlib


class Dumper:
    def __init__(self, session):

        self._session = session
        pass

    def load(self, dump_module):
        try:
            return importlib.import_module("lsassy.dumpmethod.{}".format(dump_module.lower()), "DumpMethod").DumpMethod(self._session)
        except ModuleNotFoundError:
            logging.warning("Dump module '{}' doesn't exist".format(dump_module))
            return None
        except Exception:
            logging.warning("Unknown error while loading '{}'".format(dump_module), exc_info=True)
            return None
