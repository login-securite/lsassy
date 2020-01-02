import json
from lsassy.log import Logger


class Parser():
    def __init__(self, pypydump, log):
        self._pypydump = pypydump
        self._log = log
        self._credentials = []
    
    def _parse(self, raw=False):
        ssps = ['msv_creds', 'wdigest_creds', 'ssp_creds', 'livessp_creds', 'kerberos_creds', 'credman_creds', 'tspkg_creds']
        for luid in self._pypydump.logon_sessions:
            
            for ssp in ssps:
                for cred in getattr(self._pypydump.logon_sessions[luid], ssp, []):
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
                    if raw:
                        self._credentials.append([ssp, domain, username, password, LMHash, NThash])
                    elif (not all(v is None or v == '' for v in [password, LMHash, NThash])
                            and username is not None
                            and not username.endswith('$')
                            and not username == ''):
                        self._credentials.append((ssp, domain, username, password, LMHash, NThash))

    def _decode(self, data):
        """
        Ugly trick because of mixed content coming back from pypykatz
        Can be either string, bytes, None
        """
        try:
            return data.decode('utf-8', 'backslashreplace')
        except:
            return data

    def output(self, args):
        self._parse(args.raw)
        if args.json:
            json_output = {}
            for cred in self._credentials:
                ssp, domain, username, password, lhmash, nthash = cred

                domain = self._decode(domain)
                username = self._decode(username)
                password = self._decode(password)

                if domain not in json_output:
                    json_output[domain] = {}
                if username not in json_output[domain]:
                    json_output[domain][username] = []
                credential = {
                    "password": password,
                    "lmhash": lhmash,
                    "nthash": nthash
                }
                if credential not in json_output[domain][username]:
                    json_output[domain][username].append(credential)
            print(json.dumps(json_output), end='')
        elif args.grep:
            credentials = set()
            for cred in self._credentials:
                credentials.add(':'.join([self._decode(c) if c is not None else '' for c in cred]))
            for cred in credentials:
                print(cred)
        else:
            if len(self._credentials) == 0:
                self._log.error('No credentials found')
                return 0

            max_size = max(len(c[1]) + len(c[2]) for c in self._credentials)
            credentials = []
            for cred in self._credentials:
                ssp, domain, username, password, lhmash, nthash = cred
                domain = self._decode(domain)
                username = self._decode(username)
                password = self._decode(password)
                if password is None:
                    password = ':'.join(h for h in [lhmash, nthash] if h is not None)
                if [domain, username, password] not in credentials:
                    credentials.append([domain, username, password])
                    self._log.success(
                        "{}\\{}{}{}".format(
                            domain,
                            username,
                            " " * (max_size - len(domain) - len(username) + 2),
                            Logger.highlight(password)),
                        force=True
                    )
