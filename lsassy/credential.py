class Credential:
    """
    Credential class to hold extracted credentials from remote hosts
    """
    def __init__(self, username, password=None, domain=None, lmhash=None, nthash=None, sha1=None, ticket=None, ssp=None, masterkey=None):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.sha1 = sha1
        self.ticket = ticket
        self.ssp = ssp
        self.masterkey = masterkey

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
        except Exception:
            return data

    def get_object(self):
        """
        Transform credential instance into dictionary
        :return: dict with credentials information
        """
        return {
            "username": self.username,
            "password": self.password,
            "domain": self.domain,
            "lmhash": self.lmhash,
            "nthash": self.nthash,
            "sha1": self.sha1,
            "ticket": self.ticket,
            "ssp": self.ssp,
            "masterkey": self.masterkey,
        }
