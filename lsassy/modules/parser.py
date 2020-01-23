# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]



from pypykatz.pypykatz import pypykatz

from lsassy.utils.defines import *


class Parser:
    class Options:
        def __init__(self, raw=False):
            self.raw = raw

    def __init__(self, dumpfile, options=Options()):
        self._log = dumpfile.get_connection().get_logger()
        self._dumpfile = dumpfile
        self._raw = options.raw
        self._credentials = []
    
    def parse(self):
        pypy_parse = pypykatz.parse_minidump_external(self._dumpfile)
        self._dumpfile.close()

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
                    # Remove empty password, machine accounts and buggy entries
                    if self._raw:
                        self._credentials.append([ssp, domain, username, password, LMHash, NThash])
                    elif (not all(v is None or v == '' for v in [password, LMHash, NThash])
                            and username is not None
                            and not username.endswith('$')
                            and not username == ''):
                        self._credentials.append((ssp, domain, username, password, LMHash, NThash))
        return RetCode(ERROR_SUCCESS)

    def get_credentials(self):
        return self._credentials

    def clean(self):
        return RetCode(ERROR_SUCCESS)


