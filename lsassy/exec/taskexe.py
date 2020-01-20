# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

# Based on Impacket atexec implementation by @agsolino
# https://github.com/SecureAuthCorp/impacket/blob/429f97a894d35473d478cbacff5919739ae409b4/examples/atexec.py

import random
import string
import time

from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL


class TASK_EXEC:
    def __init__(self, conn, log):
        self._conn = conn
        self._log = log

        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % self._conn.hostname
        self._rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(self._rpctransport, 'set_credentials'):
            self._rpctransport.set_credentials(self._conn.username, self._conn.password, self._conn.domain_name, self._conn.lmhash, self._conn.nthash)

    def execute(self, commands):
        dce = self._rpctransport.get_dce_rpc()

        dce.set_credentials(*self._rpctransport.get_credentials())
        dce.connect()
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        xml = self.gen_xml(commands)
        tmpName = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        self._log.debug("Register random task {}".format(tmpName))
        tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        tsch.hSchRpcRun(dce, '\\%s' % tmpName)
        done = False
        while not done:
            resp = tsch.hSchRpcGetLastRunInfo(dce, '\\%s' % tmpName)
            if resp['pLastRuntime']['wYear'] != 0:
                done = True
            else:
                time.sleep(2)

        time.sleep(3)
        tsch.hSchRpcDelete(dce, '\\%s' % tmpName)
        dce.disconnect()

    def gen_xml(self, commands):

        return """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
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
    {}
  </Actions>
</Task>
""".format(self.gen_commands(commands))

    def gen_commands(self, commands):
        ret = ""
        for command in commands:
            ret += """
     <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/C {}</Arguments>
     </Exec>""".format(command)

        return ret
