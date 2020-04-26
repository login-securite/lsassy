import logging


class Credential:
    def __init__(self, username="", password="", domain="", lmhash="", nthash="", ssp=""):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.ssp = ssp

    def get_username(self):
        return self.username

    def get_password(self):
        return self.password

    def get_domain(self):
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
        return {
            "username": self.username,
            "password": self.password,
            "domain": self.domain,
            "lmhash": self.lmhash,
            "nthash": self.nthash,
            "ssp": self.ssp
        }
