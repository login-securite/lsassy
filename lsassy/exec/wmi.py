import logging
from lsassy.exec.iexec import IExec
import socket

from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL

class Exec(IExec):
    """
    Remote execution using WMI as provided user

    This execution method does not provide debug privilege
    """
    debug_privilege = False

    def __init__(self, session):
        super().__init__(session)
        self.win32Process = None
        self.iWbemServices = None
        self.buffer = ""
        self.dcom = None

    def _buffer_callback(self, data):
        self.buffer += str(data)

    def _getwin32process(self):
        if self.session.kerberos:
            logging.debug("Trying to authenticate using kerberos ticket")
        else:
            logging.debug("Trying to authenticate using : {}\\{}:{}".format(
                self.session.domain,
                self.session.username,
                self.session.password)
            )

        try:
            self.dcom = DCOMConnection(
                self.session.address,
                self.session.username,
                self.session.password,
                self.session.domain,
                self.session.lmhash,
                self.session.nthash,
                self.session.aesKey,
                oxidResolver=True,
                doKerberos=self.session.kerberos,
                kdcHost=self.session.dc_ip
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
            raise Exception("WMIEXEC not supported on host %s : %s" % (self.session.address, e))

    def exec(self, command):
        super().exec(command)
        try:
            self._getwin32process()
            self.win32Process.Create(command, "C:\\", None)
            self.iWbemServices.disconnect()
            self.dcom.disconnect()
        except KeyboardInterrupt as e:
            logging.debug("WMI Execution stopped because of keyboard interruption")
            self.iWbemServices.disconnect()
            self.dcom.disconnect()
            raise KeyboardInterrupt(e)
        except Exception as e:
            logging.debug("Error : {}".format(e))
            self.iWbemServices.disconnect()
            self.dcom.disconnect()
