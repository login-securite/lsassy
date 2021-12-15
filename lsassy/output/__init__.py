class IOutput:
    """
    Ouput interface
    """

    def __init__(self, credentials, users_only=False, tickets=False):
        self._credentials = self.get_credentials(credentials, users_only, tickets)

    @staticmethod
    def _decode(data):
        """
        Ugly trick because of mixed content coming back from pypykatz
        Can be either string, bytes, None
        """
        try:
            return data.decode('utf-8', 'backslashreplace')
        except Exception:
            return data

    @staticmethod
    def get_credentials(credentials, users_only=False, tickets=False):
        """
        Get list of credentials with potential filtering depending on users_only flag
        :param credentials: List of credentials instances
        :param users_only: If set, only returns users account, else returns users and computers accounts
        :param tickets: If set, also returns valid TGT
        :return: List of credentials dict
        """
        return [cred.get_object() for cred in credentials if (tickets or cred.ticket is None) and not (users_only and cred.get_username().endswith("$"))]

    def get_output(self):
        """
        To be implemented in output methods
        """
        raise NotImplementedError