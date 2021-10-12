import logging
import os
import ntpath
from lsassy.credential import Credential
from pypykatz.pypykatz import pypykatz


class Parser:
    """
    Parse remote lsass dump file using impacketfile and pypykatz
    """

    def __init__(self, dumpfile):
        self._dumpfile = dumpfile

    def parse(self):
        """
        Parse remote dump file and delete it after parsing
        :return: List of Credentials
        """
        credentials = []
        tickets = []
        try:
            pypy_parse = pypykatz.parse_minidump_external(self._dumpfile, chunksize = 60*1024)
        except Exception as e:
            logging.error("An error occurred while parsing lsass dump", exc_info=True)
            return None

        ssps = ['msv_creds', 'wdigest_creds', 'ssp_creds', 'livessp_creds', 'kerberos_creds', 'credman_creds',
                'tspkg_creds']
        for luid in pypy_parse.logon_sessions:

            for ssp in ssps:
                for cred in getattr(pypy_parse.logon_sessions[luid], ssp, []):
                    domain = getattr(cred, "domainname", None)
                    username = getattr(cred, "username", None)
                    password = getattr(cred, "password", None)
                    LMHash = getattr(cred, "LMHash", None)
                    NThash = getattr(cred, "NThash", None)
                    SHA1 = getattr(cred, "SHAHash", None)
                    if LMHash is not None:
                        LMHash = LMHash.hex()
                    if NThash is not None:
                        NThash = NThash.hex()
                    if SHA1 is not None:
                        SHA1 = SHA1.hex()
                    if username and (password or NThash or LMHash):
                        credentials.append(
                            Credential(ssp=ssp, domain=domain, username=username, password=password, lmhash=LMHash,
                                       nthash=NThash, sha1=SHA1))

            for kcred in pypy_parse.logon_sessions[luid].kerberos_creds:
                for ticket in kcred.tickets:
                    tickets.append(ticket)

        for cred in pypy_parse.orphaned_creds:
            if cred.credtype == 'kerberos':
                for ticket in cred.tickets:
                    tickets.append(ticket)

        return credentials, tickets
