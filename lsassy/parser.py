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

    def parse(self,kerberos_dir,parse_only=False):
        """
        Parse remote dump file and delete it after parsing
        :return: List of Credentials
        """
        credentials = []
        try:
            pypy_parse = pypykatz.parse_minidump_external(self._dumpfile)
        except Exception as e:
            logging.error("An error occurred while parsing lsass dump", exc_info=True)
            print(self._dumpfile.read(10))
            return None

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

        if kerberos_dir:
            dir = os.path.abspath(kerberos_dir)
            logging.success("Writing kerberos tickets to %s" % dir)
            ccache_filename = '%s.ccache' % (os.urandom(4).hex()) #to avoid collisions
            pypy_parse.kerberos_ccache.to_file(os.path.join(dir, ccache_filename))
            for luid in pypy_parse.logon_sessions:
                for kcred in pypy_parse.logon_sessions[luid].kerberos_creds:
                    for ticket in kcred.tickets:
                        ticket.to_kirbi(dir)

            for cred in pypy_parse.orphaned_creds:
                if cred.credtype == 'kerberos':
                    for ticket in cred.tickets:
                        ticket.to_kirbi(dir)

        return credentials
