import logging
from impacket.smbconnection import SMBConnection


class Session:
    """
    Custom impacket SMB session
    """
    def __init__(self, smb_session=None):
        self.smb_session = smb_session
        self.address = ""
        self.target_ip = ""
        self.port = 445
        self.username = ""
        self.password = ""
        self.lmhash = ""
        self.nthash = ""
        self.domain = ""
        self.aesKey = ""
        self.dc_ip = ""
        self.kerberos = False
        self.timeout = 5

    def get_session(self, address, target_ip="", port=445, username="", password="", lmhash="", nthash="", domain="", aesKey="", dc_ip="", kerberos=False, timeout=5):
        """
        Login on remote host
        :param address: Remote host
        :param target_ip: Remote host IP address
        :param port: Remote port
        :param username: Username
        :param password: Password
        :param lmhash: LM Hash
        :param nthash: NT Hash
        :param domain: Domain
        :param aesKey: AES Key
        :param dc_ip: Domain Controller IP address
        :param kerberos: Use kerberos
        :return: SMB Session
        """
        try:
            self.smb_session = SMBConnection(address, target_ip, None, sess_port=port, timeout=timeout)
        except Exception:
            logging.warning("Network error", exc_info=True)
            self.smb_session = None
            return None

        try:
            if kerberos is True:
                self.smb_session.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, dc_ip)
            else:
                self.smb_session.login(username, password, domain, lmhash, nthash)
            logging.info("SMB session opened")
        except Exception as e:
            if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in str(e):
                logging.error("Connexion error (Use FQDN for kerberos authentication)", exc_info=True)
            else:
                logging.warning("Connexion error", exc_info=True)
            self.smb_session = None
            return None

        try:
            self.smb_session.connectTree("C$")
        except Exception:
            if username:
                logging.error("User '{}' can not access admin shares on {}".format(username, address))
            else:
                logging.error("Can not access admin shares on {}".format(address))
            self.smb_session = None
            return None

        self.address = address
        self.target_ip = target_ip
        self.port = port
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.domain = domain
        self.aesKey = aesKey
        self.dc_ip = dc_ip
        self.kerberos = kerberos
        self.timeout = timeout

        logging.success("Authentication successful")
        return True

    def login(self):
        return self.get_session(self.address, self.target_ip, self.port, self.username, self.password, self.lmhash,
                         self.nthash, self.domain, self.aesKey, self.dc_ip, self.kerberos, self.timeout)
