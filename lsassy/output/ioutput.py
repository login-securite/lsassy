import logging
import os
from pathlib import Path
import importlib


class IOutput:
    """
    Ouput interface
    """

    def __init__(self, credentials, users_only=False, dpapi=False):
        self._credentials = self.get_credentials(credentials, users_only, dpapi)

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

    def get_credentials(self, credentials, users_only=False, dpapi=False):
        """
        Get list of credentials with potential filtering depending on users_only flag
        :param credentials: List of credentials instances
        :param users_only: If set, only returns users account, else returns users and computers accounts
        :return: List of credentials dict
        """
        return [cred.get_object() for cred in credentials if dpapi or not (users_only and cred.get_username().endswith("$"))]

    def get_output(self):
        """
        To be implemented in output methods
        """
        raise NotImplementedError

    def get_dpapi_output(self):
        """
        To be implemented in output methods
        """
        raise NotImplementedError