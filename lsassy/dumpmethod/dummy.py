import logging
import os
import time

from lsassy.dumpmethod.idumpmethod import IDumpMethod


class DumpMethod(IDumpMethod):
    """
    Dummy dump class that can be used to implement your own dumping method
    """

    """
    If your dumping method cannot produce a dumpfile with a custom dumpfile name, you must set this setting to False
    and uncomment 'dump_name' to provide expected dumpfile name on remote system.
    """
    custom_dump_name_support = True  # Default: True
    # dump_name              = ""    # Default: Random dumpfile name

    """
    If your dumping method cannot produce a dumpfile in a custom directory, you must set this setting to False
    and uncomment 'dump_share' and 'dump_path' to provide expected dumpfile location on remote system.
    """
    custom_dump_path_support = True  # Default: True
    # dump_share             = ""    # Default: "C$"
    # dump_path              = ""    # Default: "\\Windows\\Temp\\"

    def __init__(self, session, timeout):
        """
        * Optional *
        Initiates self._session and self._file in super().
        Do not remove "super().__init__(session)" call if keeping __init__
        """
        super().__init__(session, timeout)

        """
        You can set custom variable in this section for later use
        """
        # self.tool = "/opt/tools/tool.exe"

    def get_commands(self):
        """
        * Mandatory *
        Build dump commands.
        :return: Dumping commands
        """
        cmd_command = ""
        pwsh_command = ""
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }

    def prepare(self, options):
        """
        * Optional *
        Called before executing dump command. Can be useful to upload necessary tools for dumping lsass.
        See procdump.py for example
        :param options: Dictionary containing all unexpected parameters provided in get_dump_file()
        """
        # self.tool = options.get("tool", self.tool)
        # Upload self.tool to remote server

    def clean(self):
        """
        * Optional *
        Called after executing dump command. Can be useful to remove uploaded tools.
        See procdump.py for example
        """
        # Delete self.tool on remote server
