# Based on Impacket wmiexec implementation by @agsolino
# https://github.com/SecureAuthCorp/impacket/blob/429f97a894d35473d478cbacff5919739ae409b4/examples/wmiexec.py

import socket
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL


class WMI:
    def __init__(self, connexion, logger):
        self.conn = connexion
        self.conn.hostname = list({addr[-1][0] for addr in socket.getaddrinfo(self.conn.hostname, 0, 0, 0, 0)})[0]
        self.log = logger
        self.win32Process = None
        self.buffer = ""
        self.dcom = None
        self._getwin32process()

    def _buffer_callback(self, data):
        self.buffer += str(data)

    def _getwin32process(self):
        self.log.debug("Trying to authenticate using {}\\{}:{}".format(
            self.conn.domain_name,
            self.conn.username,
            self.conn.password)
        )
        self.dcom = DCOMConnection(
            self.conn.hostname,
            self.conn.username,
            self.conn.password,
            self.conn.domain_name,
            self.conn.lmhash,
            self.conn.nthash,
            None,
            oxidResolver=True,
            doKerberos=False
        )
        try:
            iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
            self.win32Process, _ = iWbemServices.GetObject('Win32_Process')
        except Exception as e:
            raise Exception("WMIEXEC not supported on host %s : %s" % (self.conn.hostname, e))

    def execute(self, command):
        self.win32Process.Create(command, "C:\\", None)
        self.dcom.disconnect()
