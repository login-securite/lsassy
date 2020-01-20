# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

# Based on Impacket wmiexec implementation by @agsolino
# https://github.com/SecureAuthCorp/impacket/blob/429f97a894d35473d478cbacff5919739ae409b4/examples/wmiexec.py

import socket

from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL


class WMI:
    def __init__(self, connection, logger):
        self.conn = connection
        self.conn.hostname = list({addr[-1][0] for addr in socket.getaddrinfo(self.conn.hostname, 0, 0, 0, 0)})[0]
        self.log = logger
        self.win32Process = None
        self.iWbemServices = None
        self.buffer = ""
        self.dcom = None
        self._getwin32process()

    def _buffer_callback(self, data):
        self.buffer += str(data)

    def _getwin32process(self):
        self.log.debug("Trying to authenticate using : {}\\{}:{}".format(
            self.conn.domain_name,
            self.conn.username,
            self.conn.password)
        )

        try:
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
            iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            self.iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
            self.win32Process, _ = self.iWbemServices.GetObject('Win32_Process')
        except KeyboardInterrupt as e:
            self.dcom.disconnect()
            raise KeyboardInterrupt(e)
        except Exception as e:
            raise Exception("WMIEXEC not supported on host %s : %s" % (self.conn.hostname, e))

    def execute(self, commands):
        command = " & ".join(commands)
        try:
            self.win32Process.Create(command, "C:\\", None)
            self.iWbemServices.disconnect()
            self.dcom.disconnect()
        except KeyboardInterrupt as e:
            self.log.debug("WMI Execution stopped because of keyboard interruption")
            self.iWbemServices.disconnect()
            self.dcom.disconnect()
            raise KeyboardInterrupt(e)
        except Exception as e:
            self.log.debug("Error : {}".format(e))
            self.iWbemServices.disconnect()
            self.dcom.disconnect()
