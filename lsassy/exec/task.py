# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

# Based on Impacket atexec implementation by @agsolino
# https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py

import logging
import random
import string
import time

from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from lsassy.exec import IExec


class Exec(IExec):
    """
    Remote execution using task creation as SYSTEM

    This execution method provides debug privilege
    """
    debug_privilege = True

    def __init__(self, session):
        super().__init__(session)
        self._rpctransport = None
        self._dce = None
        self._taskname = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))

    def exec(self, command):
        if not super().exec(command):
            return False
        try:
            stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % self.session.address
            self._rpctransport = transport.DCERPCTransportFactory(stringbinding)

            if hasattr(self._rpctransport, 'set_credentials'):
                self._rpctransport.set_credentials(self.session.username, self.session.password, self.session.domain,
                                                   self.session.lmhash, self.session.nthash, self.session.aesKey)
                self._rpctransport.set_kerberos(self.session.kerberos, self.session.dc_ip)
            self._dce = self._rpctransport.get_dce_rpc()
            self._dce.set_credentials(*self._rpctransport.get_credentials())
            if self.session.kerberos:
                self._dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            self._dce.connect()
            self._dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self._dce.bind(tsch.MSRPC_UUID_TSCHS)
            xml = self.gen_xml(command)
            logging.debug("Register random task {}".format(self._taskname))
            tsch.hSchRpcRegisterTask(self._dce, '\\%s' % self._taskname, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            tsch.hSchRpcRun(self._dce, '\\%s' % self._taskname)
            done = False
            while not done:
                resp = tsch.hSchRpcGetLastRunInfo(self._dce, '\\%s' % self._taskname)
                if resp['pLastRuntime']['wYear'] != 0:
                    done = True
                else:
                    time.sleep(2)

            time.sleep(3)
            self.clean()
        except KeyboardInterrupt as e:
            self.clean()
            raise KeyboardInterrupt(e)
        except Exception as e:
            self.clean()
            raise Exception(e)
        return True
    
    def clean(self):
        resp = tsch.hSchRpcEnumInstances(self._dce, '\\%s' % self._taskname)
        if len(resp['pGuids']) != 0:
            tsch.hSchRpcStopInstance(self._dce, resp['pGuids'][0])
        tsch.hSchRpcDelete(self._dce, '\\%s' % self._taskname)
        self._dce.disconnect()
        logging.debug("Task %s has been removed" % self._taskname)
            
    def gen_xml(self, command):

        return """<?xml version="1.0" encoding="UTF-16"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers>
        <TimeTrigger>
          <StartBoundary>1989-09-17T02:20:00</StartBoundary>
          <Enabled>true</Enabled>
        </TimeTrigger>
      </Triggers>
      <Principals>
        <Principal id="LocalSystem">
          <UserId>S-1-5-18</UserId>
          <RunLevel>HighestAvailable</RunLevel>
        </Principal>
      </Principals>
      <Settings>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <AllowHardTerminate>true</AllowHardTerminate>
        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
        <IdleSettings>
          <StopOnIdleEnd>true</StopOnIdleEnd>
          <RestartOnIdle>false</RestartOnIdle>
        </IdleSettings>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>true</Hidden>
        <RunOnlyIfIdle>false</RunOnlyIfIdle>
        <WakeToRun>false</WakeToRun>
        <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
        <Priority>7</Priority>
      </Settings>
      <Actions Context="LocalSystem">
        <Exec>
          <Command>cmd.exe</Command>
          <Arguments>/C {}</Arguments>
         </Exec>
      </Actions>
    </Task>
    """.format(command.replace("&", "&#38;").replace("<", "&#60;").replace(">", "&#62;"))
