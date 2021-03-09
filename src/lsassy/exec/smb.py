import logging

from impacket.dcerpc.v5 import transport, scmr
from lsassy.exec.iexec import IExec


class Exec(IExec):
    """
    Remote execution using task creation as SYSTEM

    This execution method provides debug privilege
    """
    debug_privilege = True

    def __init__(self, session):
        super().__init__(session)

    def exec(self, command):
        _serviceName = "lsassySvc"
        super().exec(command)
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % self.session.address
        logging.debug('StringBinding %s' % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(445)
        rpctransport.setRemoteHost(self.session.address)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.session.username, self.session.password, self.session.domain,
                                               self.session.lmhash, self.session.nthash, self.session.aesKey)
        rpctransport.set_kerberos(self.session.kerberos, self.session.dc_ip)
        _scmr = rpctransport.get_dce_rpc()
        try:
            _scmr.connect()
        except Exception as e:
            raise Exception("An error occurred while connecting to SVCCTL: %s" % e)

        s = rpctransport.get_smb_connection()
        s.setTimeout(100000)
        _scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(_scmr)
        _scHandle = resp['lpScHandle']
        transferClient = rpctransport.get_smb_connection()
        resp = scmr.hRCreateServiceW(_scmr, _scHandle, _serviceName, _serviceName, lpBinaryPathName=command,
                                     dwStartType=scmr.SERVICE_DEMAND_START)
        logging.debug("Service %s created" % _serviceName)
        service = resp['lpServiceHandle']
        try:
            scmr.hRStartServiceW(_scmr, service)
            logging.debug("Service %s restarted for command execution" % _serviceName)
        except:
            pass

        try:
            scmr.hRDeleteService(_scmr, service)
            scmr.hRCloseServiceHandle(_scmr, service)
            logging.debug("Service %s deleted" % _serviceName)
        except:
            logging.warning("An error occurred while trying to delete service %s. Trying again." % _serviceName)
            try:
                _scmr = rpctransport.get_dce_rpc()
                _scmr.connect()
                _scmr.bind(scmr.MSRPC_UUID_SCMR)
                resp = scmr.hROpenSCManagerW(_scmr)
                _scHandle = resp['lpScHandle']
                resp = scmr.hROpenServiceW(_scmr, _scHandle, _serviceName)
                service = resp['lpServiceHandle']
                scmr.hRDeleteService(_scmr, service)
                logging.debug("Service %s deleted" % _serviceName)
                scmr.hRControlService(_scmr, service, scmr.SERVICE_CONTROL_STOP)
                scmr.hRCloseServiceHandle(_scmr, service)
            except scmr.DCERPCException:
                pass
