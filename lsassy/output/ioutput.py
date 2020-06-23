import logging
import os
from pathlib import Path
import importlib


class IOutput:

    def __init__(self, credentials, users_only=False):
        self._credentials = self.get_credentials(credentials, users_only)

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

    def get_credentials(self, credentials, users_only=False):
        return [cred.get_object() for cred in credentials if not (users_only and cred.get_username().endswith("$"))]

    def get_output(self):
        raise NotImplementedError