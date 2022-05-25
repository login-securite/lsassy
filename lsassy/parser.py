from doctest import master
import logging
from datetime import datetime

from pypykatz.pypykatz import pypykatz

from lsassy.credential import Credential


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
        masterkeys = []
        try:
            pypy_parse = pypykatz.parse_minidump_external(self._dumpfile, chunksize = 60*1024)
        except Exception as e:
            logging.error("An error occurred while parsing lsass dump", exc_info=True)
            return None

        ssps = ['msv_creds', 'wdigest_creds', 'ssp_creds', 'livessp_creds', 'kerberos_creds', 'credman_creds',
                'tspkg_creds', 'dpapi_creds']
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
                    if username and (password
                                     or (NThash and NThash != "00000000000000000000000000000000")
                                     or (LMHash and LMHash != "00000000000000000000000000000000")):
                        credentials.append(
                            Credential(ssp=ssp, domain=domain, username=username, password=password, lmhash=LMHash,
                                       nthash=NThash, sha1=SHA1))

            for kcred in pypy_parse.logon_sessions[luid].kerberos_creds:
                for ticket in kcred.tickets:
                    tickets.append(ticket)

            for dpapicred in pypy_parse.logon_sessions[luid].dpapi_creds:
                m = "{%s}:%s" % (dpapicred.key_guid,dpapicred.sha1_masterkey)
                if m not in masterkeys:
                    masterkeys.append(m)
                    credentials.append(
                        Credential(ssp='dpapi', domain='', username='', masterkey=m)
                    )

        for cred in pypy_parse.orphaned_creds:
            if cred.credtype == 'kerberos':
                for ticket in cred.tickets:
                    tickets.append(ticket)

        for ticket in tickets:
            if ticket.ServiceName is not None and ticket.ServiceName[0] == 'krbtgt':
                if ticket.EClientName is not None and ticket.DomainName is not None:
                    if ticket.TargetDomainName is not None and ticket.TargetDomainName != ticket.DomainName:
                        target_domain = ticket.TargetDomainName
                    else:
                        target_domain = ticket.DomainName
                    # Keep only valid tickets
                    if ticket.EndTime > datetime.now(ticket.EndTime.tzinfo):

                        credentials.append(Credential(
                            ssp="kerberos",
                            domain=ticket.DomainName,
                            username=ticket.EClientName[0],
                            ticket={'file': list(ticket.kirbi_data)[0], 'domain': target_domain, 'endtime': ticket.EndTime}
                        ))

        return credentials, tickets, masterkeys
