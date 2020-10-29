import logging


class Credential:
    """
    Credential class to hold extracted credentials from remote hosts
    """
    def __init__(self, source="", username="", password="", domain="", lmhash="", nthash="", ssp="", data=None):
        self.source = source
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.ssp = ssp
        self.data = data

    def set_source(self, source):
        self.source = source

    def get_username(self):
        """
        Get credential username
        :return: username
        """
        return self.username

    def get_password(self):
        """
        Get credential password
        :return: password
        """
        return self.password

    def get_domain(self):
        """
        Get credential domain
        :return: domain
        """
        return self.domain

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

    def get_object(self):
        """
        Transform credential instance into dictionary
        :return: dict with credentials information
        """
        return {
            "source": self.source,
            "username": self.username,
            "password": self.password,
            "domain": self.domain,
            "lmhash": self.lmhash,
            "nthash": self.nthash,
            "ssp": self.ssp,
            "data": self.data
        }
