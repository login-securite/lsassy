import logging
import os
from pathlib import Path
import importlib


class IOutput:

    def __init__(self, credentials):
        self._credentials = self.get_credentials(credentials)

    @staticmethod
    def _decode(data):
        """
        Ugly trick because of mixed content coming back from pypykatz
        Can be either string, bytes, None
        """
        try:
            return data.decode('utf-8', 'backslashreplace')
        except:
            return data

    def get_credentials(self, credentials):
        return [cred.get_object() for cred in credentials]

    def get_output(self):
        raise NotImplementedError