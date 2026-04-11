import tempfile
import ntpath
import os.path

from impacket.smbconnection import SMBConnection
from pypsrp.client import Client as WinrmClient

from lsassy.logger import lsassy_logger


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

    def get_session(
        self,
        address,
        target_ip="",
        port=445,
        username="",
        password="",
        lmhash="",
        nthash="",
        domain="",
        aesKey="",
        dc_ip="",
        kerberos=False,
        timeout=5,
    ):
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
            self.smb_session = SMBConnection(
                address, target_ip, None, sess_port=port, timeout=timeout
            )
        except Exception:
            lsassy_logger.warning("Network error", exc_info=True)
            self.smb_session = None
            return None
        lsassy_logger.debug(f"smb_session: {self.smb_session}")

        try:
            if kerberos is True:
                self.smb_session.kerberosLogin(
                    username, password, domain, lmhash, nthash, aesKey, dc_ip
                )
            else:
                self.smb_session.login(username, password, domain, lmhash, nthash)
            lsassy_logger.info("SMB session opened")
        except Exception as e:
            if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in str(e):
                lsassy_logger.error(
                    "Connection error (Use FQDN for kerberos authentication)",
                    exc_info=True,
                )
            else:
                lsassy_logger.error("Connection error", exc_info=True)
            self.smb_session = None
            return None

        try:
            lsassy_logger.debug("Connecting to C$")
            self.smb_session.connectTree("C$")
        except Exception:
            if username:
                lsassy_logger.error(
                    "User '{}' can not access admin shares on {}".format(
                        username, address
                    )
                )
            else:
                lsassy_logger.error("Can not access admin shares on {}".format(address))
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

        lsassy_logger.info("Authentication successful")
        return True

    def login(self):
        return self.get_session(
            self.address,
            self.target_ip,
            self.port,
            self.username,
            self.password,
            self.lmhash,
            self.nthash,
            self.domain,
            self.aesKey,
            self.dc_ip,
            self.kerberos,
            self.timeout,
        )

    def correct_file_handler(self):
        from impacketfile import ImpacketFile
        return ImpacketFile

class WinrmSession:
    """
    custom winrm session based on pypsrp - works as drop-in replacement for the smb session object
    this has been inspired by the most awesome nxc
    """

    def __init__(self):
        self.smb_session = None
        self.address = ""
        self.target_ip = ""
        self.port = 5985
        self.username = ""
        self.password = ""
        self.lmhash = ""
        self.nthash = ""
        self.domain = ""
        self.aesKey = ""
        self.dc_ip = ""
        self.kerberos = False
        self.timeout = 5

    def get_session(
            self,
            address,
            target_ip="",
            port=5985,
            username="",
            password="",
            lmhash="00000000000000000000000000000000",
            nthash="",
            domain="",
            aesKey="",
            dc_ip="",
            kerberos=False,
            timeout=5,
    ):
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
            server = target_ip if target_ip else address
            username = f"{domain}\\{username}"
            password = password if not nthash else f"{lmhash}:{nthash}"
            auth = "ntlm" if not kerberos else "kerberos"
            self.smb_session = WinrmClient(server, port=port, username=username, password=password, auth=auth, cert_validation=False, ssl=False)
            # if this fails the authentication has failed too
            self.smb_session.execute_ps("whoami")
        except Exception as e:
            if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in str(e):
                lsassy_logger.error("Connection error (Use FQDN for kerberos authentication)", exc_info=True)
            else:
                lsassy_logger.error("Connection error", exc_info=True)
            self.smb_session = None
            return None
        lsassy_logger.debug(f"smb_session (actually winrm): {self.smb_session}")
        lsassy_logger.info("WinRM session opened")

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

        lsassy_logger.info("Authentication successful")
        # patching get and put file methods.... this must be refactored ASAP!
        self.smb_session.putFile = self.putFile
        self.smb_session.getFile = self.getFile
        return True

    def login(self):
        return self.get_session(
            self.address,
            self.target_ip,
            self.port,
            self.username,
            self.password,
            self.lmhash,
            self.nthash,
            self.domain,
            self.aesKey,
            self.dc_ip,
            self.kerberos,
            self.timeout,
        )

    def copy(self, local_path, remote_path):
        return self.smb_session.copy(local_path, remote_path, expand_variables=True)

    def fetch(self, remote_path, local_path):
        return self.smb_session.fetch(remote_path, local_path, expand_variables=True)

    def correct_file_handler(self):
        from lsassy.winrmfile import WinrmFile
        return WinrmFile

    def getFile(self, share, path, buffer_method):
        """getFile

        modelled after smb getFile designed to be a drop in replacement"""
        share = share.replace("$", ":")
        path = path.replace("\\", "/")
        full_remote_path = ntpath.join(share, path)
        with tempfile.NamedTemporaryFile() as tmp:
            full_tmp_path = os.path.join(tempfile.gettempdir(), tmp.name)
            self.fetch(full_remote_path, full_tmp_path)
            tmp.seek(0)
            buffer_method(tmp.read())

    def putFile(self, share, path, buffer_method):
        """putFile

        modelled after smb putFile designed to be a drop in replacement"""
        share = share.replace("$", ":")
        path = path.replace("\\", "/")
        full_remote_path = ntpath.join(share, path)
        buffer = b""
        with tempfile.NamedTemporaryFile() as tmp:
            full_tmp_path = os.path.join(tempfile.gettempdir(), tmp.name)
            while True:
                data = buffer_method(1024)
                buffer += data
                if data == b"": break
            tmp.write(buffer)
            tmp.seek(0)
            self.copy(full_tmp_path, full_remote_path)
