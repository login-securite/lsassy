import logging
from lsassy.credential import Credential
from pypykatz.pypykatz import pypykatz


class Parser:
    """
    Parse remote lsass dump file using impacketfile and pypykatz
    """
    def __init__(self, dumpfile):
        self._dumpfile = dumpfile

    def parse(self, parse_only=False):
        """
        Parse remote dump file and delete it after parsing
        :return: List of Credentials
        """
        credentials = []
        pypy_parse = pypykatz.parse_minidump_external(self._dumpfile)

        ssps = ['msv_creds', 'wdigest_creds', 'ssp_creds', 'livessp_creds', 'kerberos_creds', 'credman_creds', 'tspkg_creds']
        for luid in pypy_parse.logon_sessions:

            for ssp in ssps:
                for cred in getattr(pypy_parse.logon_sessions[luid], ssp, []):
                    domain = getattr(cred, "domainname", None)
                    username = getattr(cred, "username", None)
                    password = getattr(cred, "password", None)
                    LMHash = getattr(cred, "LMHash", None)
                    NThash = getattr(cred, "NThash", None)
                    if LMHash is not None:
                        LMHash = LMHash.hex()
                    if NThash is not None:
                        NThash = NThash.hex()
                    if username and (password or NThash or LMHash):
                        credentials.append(Credential(ssp=ssp, domain=domain, username=username, password=password, lmhash=LMHash, nthash=NThash))
        return credentials
