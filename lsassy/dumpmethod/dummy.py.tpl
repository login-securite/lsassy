import logging
import os
import time

from lsassy.dumpmethod import IDumpMethod


class DumpMethod(IDumpMethod):
    """
    Dummy dump class that can be used to implement your own dumping method
    """

    """
    If seDebugPrivilege is needed, this should be set to True
    """
    need_debug_privilege = False     # Default: False

    """
    If your dumping method cannot produce a dumpfile with a custom dumpfile path, name or extension, you must set these
    settings to False and uncomment 'dump_name', 'dump_path' and/or 'dump_ext' to provide expected dumpfile info on
    remote system.
    """
    custom_dump_path_support = True  # Default: True
    custom_dump_name_support = True  # Default: True
    custom_dump_ext_support = True   # Default: True

    # dump_name              = ""    # Default: Random dumpfile name
    # dump_path              = ""    # Default: "\\Windows\\Temp\\"
    # dump_ext               = ""    # Default: Random dumpfile extension

    """
    If your dumping method cannot produce a dumpfile in a custom directory, you must set this setting to False
    and uncomment 'dump_share' and 'dump_path' to provide expected dumpfile location on remote system.
    """
    custom_dump_path_support = True  # Default: True
    # dump_share             = ""    # Default: "C$"

    def __init__(self, session, timeout):
        """
        * Optional *
        Initiates self._session and self._file in super().
        Do not remove "super().__init__(session)" call if keeping __init__
        """
        super().__init__(session, timeout)

        """
        You can set custom variable in this section for later use. You can also use the Dependency class if you need
        to upload some files/tools on the remote host. First argument is a name for our dependency (can be arbitrary),
        and second argument is default executable/file name on local user's disk.
        """
        # self.var = "some variable"
        # self.tool = Dependency("mytool", "MyTool.exe")

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
        See procdump.py for example. self.prepare_dependencies() can be used.
        :param options: Dictionary containing all unexpected parameters provided in get_dump_file()
        """
        # return self.prepare_dependencies(options, [self.tool])

    def clean(self):
        """
        * Optional *
        Called after executing dump command. Can be useful to remove uploaded tools. self.clean_dependencies()
        can be used.
        See procdump.py for example
        """
        # self.clean_dependencies(options, [self.tool])
