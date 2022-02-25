# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

# Based on Impacket smbexec implementation by @agsolino
# https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py

import logging
import random
import string

from impacket.dcerpc.v5 import transport, scmr

from lsassy.exec import IExec


class Exec(IExec):
    """
    Remote execution using service creation as SYSTEM

    This execution method provides debug privilege
    """
    debug_privilege = True

    def __init__(self, session):
        self._scmr = None
        self._service = None
        self._rpctransport = None
        self._serviceName = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        super().__init__(session)
        
    def clean(self):
        try:
            scmr.hRDeleteService(self._scmr, self._service)
            scmr.hRCloseServiceHandle(self._scmr, self._service)
            logging.debug("Service %s deleted" % self._serviceName)
        except:
            logging.warning("An error occurred while trying to delete service %s. Trying again." % self._serviceName)
            try:
                logging.debug("Trying to connect back to SCMR")
                self._scmr = self._rpctransport.get_dce_rpc()
                try:
                    self._scmr.connect()
                except Exception as e:
                    raise Exception("An error occurred while connecting to SVCCTL: %s" % e)
                logging.debug("Connected to SCMR")
                self._scmr.bind(scmr.MSRPC_UUID_SCMR)
                resp = scmr.hROpenSCManagerW(self._scmr)
                _scHandle = resp['lpScHandle']
                resp = scmr.hROpenServiceW(self._scmr, _scHandle, self._serviceName)
                logging.debug("Found service %s" % self._serviceName)
                self._service = resp['lpServiceHandle']
                scmr.hRDeleteService(self._scmr, self._service)
                logging.debug("Service %s deleted" % self._serviceName)
                scmr.hRControlService(self._scmr, self._service, scmr.SERVICE_CONTROL_STOP)
                scmr.hRCloseServiceHandle(self._scmr, self._service)
            except scmr.DCERPCException:
                logging.debug("A DCERPCException error occured while trying to delete %s" % self._serviceName, exc_info=True)
                pass
            except:
                logging.debug("An unknown error occured while trying to delete %s" % self._serviceName, exc_info=True)
                pass

    def exec(self, command):
        if not super().exec(command):
            return False
        try:
            stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % self.session.address
            logging.debug('StringBinding %s' % stringbinding)
            self._rpctransport = transport.DCERPCTransportFactory(stringbinding)
            self._rpctransport.set_dport(445)
            self._rpctransport.setRemoteHost(self.session.address)
            if hasattr(self._rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                self._rpctransport.set_credentials(self.session.username, self.session.password, self.session.domain,
                                                   self.session.lmhash, self.session.nthash, self.session.aesKey)
            self._rpctransport.set_kerberos(self.session.kerberos, self.session.dc_ip)
            self._scmr = self._rpctransport.get_dce_rpc()
            try:
                self._scmr.connect()
            except Exception as e:
                raise Exception("An error occurred while connecting to SVCCTL: %s" % e)
            s = self._rpctransport.get_smb_connection()
            s.setTimeout(100000)
            self._scmr.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self._scmr)
            _scHandle = resp['lpScHandle']
            resp = scmr.hRCreateServiceW(self._scmr, _scHandle, self._serviceName, self._serviceName,
                                         lpBinaryPathName="%COMSPEC% /Q /c {}".format(command),
                                         dwStartType=scmr.SERVICE_DEMAND_START)
            logging.debug("Service %s created" % self._serviceName)
            self._service = resp['lpServiceHandle']
            try:
                scmr.hRStartServiceW(self._scmr, self._service)
                logging.debug("Service %s restarted for command execution" % self._serviceName)
            except:
                pass
            self.clean()
        except KeyboardInterrupt as e:
            logging.debug("Keyboard interrupt: Trying to delete %s if it exists" % self._serviceName)
            self.clean()
            raise KeyboardInterrupt(e)
        except Exception as e:
            self.clean()
            raise Exception(e)
        return True
