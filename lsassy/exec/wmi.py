# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

# Based on Impacket wmiexec implementation by @agsolino
# https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py

import logging

from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL

from lsassy.exec import IExec


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
            self.clean()
            raise KeyboardInterrupt(e)
        except Exception as e:
            self.clean()
            raise Exception("WMIEXEC not supported on host %s : %s" % (self.session.address, e))

    def exec(self, command):
        if not super().exec(command):
            return False
        try:
            self._getwin32process()
            self.win32Process.Create(command, "C:\\", None)
            self.iWbemServices.disconnect()
            self.dcom.disconnect()
        except KeyboardInterrupt as e:
            logging.debug("WMI Execution stopped because of keyboard interruption")
            self.clean()
            raise KeyboardInterrupt(e)
        except Exception as e:
            logging.debug("Error : {}".format(e), exc_info=True)
            self.clean()
            raise Exception(e)
        return True

    def clean(self):
        try:
            self.iWbemServices.disconnect()
        except Exception as e:
            pass
        try:
            self.dcom.disconnect()
        except Exception as e:
            pass