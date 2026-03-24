import os
import tempfile
import time
from os.path import exists
import ntpath

from pypsrp.exceptions import WinRMError
from lsassy.session import WinrmSession
from lsassy.logger import lsassy_logger


class WinrmFile:
    """
    Remote file representation

    This class uses the winrm session to copy and fetch the file from remote to and from a local file.
    It is compatible with lsassy.ImpacketFile and works as a stand in.
    WARNING: only the functions which are actually used in the code are implemented!
    """

    def __init__(self, session: WinrmSession):
        self._session = session
        self._share_name = None
        self._fpath = None
        self._currentOffset = 0
        self._total_read = 0
        self._tid = None
        self._fid = None
        self._fileInfo = None
        self._endOfFile = None

        self._opened = False

        self._buffer_min_size = 1024 * 8
        self._buffer_data = {"offset": 0, "size": 0, "buffer": ""}

        self.file_mirror = tempfile.NamedTemporaryFile()

    def get_connection(self):
        """
        Method to access a private attribute
        :return: session instance
        """
        return self._session

    def _open_share(self):
        # This is not necessary - it will be implemented when there is a need
        raise NotImplementedError

    @staticmethod
    def create_file(session: WinrmSession, share: str, path: str, file: str, content):
        """create_file

        the signature of this function is due to lsassy.ImpacketFile
        share = drive letter
        path = directory path without file
        file = file name (plus extension)
        """
        path = path.replace("\\", "/")
        try:
            share = share.replace("$", ":")
            full_remote_path = ntpath.join(share, path, file)
        except Exception:
            lsassy_logger.warning("Parsing error with '{}'".format(full_remote_path), exc_info=True)
            return None

        try:
            with tempfile.NamedTemporaryFile() as tmp:
                full_tmp_path = os.path.join(tempfile.gettempdir(), tmp.name)
                tmp.write(content)
                tmp.seek(0)
                full_remote_path = session.copy(full_tmp_path, full_remote_path)
        finally:
            if full_remote_path is not None and WinrmFile.exists(session, full_remote_path):
                lsassy_logger.debug(f"File {full_remote_path} created!")
                return True
        return None

    @staticmethod
    def delete(session: WinrmSession, file_path, timeout=5):
        """delete

        the signature of this function is due to lsassy.ImpacketFile - this time the drive letter is hard coded to C
        """
        t = time.time()
        if not file_path.lower().startswith("c:"):
            file_path = ntpath.join("C:/", file_path)

        # the while loop behaviour was cargo culted from ImpacketFile
        while True:
            file_exists_before = exists(file_path)
            result = session.smb_session.execute_ps(f"del {file_path}")[0]
            file_exists_after = exists(file_path)
            if file_exists_before and not file_exists_after:
                lsassy_logger.debug(f"File {file_path} deleted")
                return True
            if not file_exists_before and not file_exists_after: # whoops
                lsassy_logger.debug(f"File {file_path} has disappeared before deletion")
                return True
            if file_exists_before and file_exists_after:
                lsassy_logger.warning(f"File wasn't removed `{file_path}`", exc_info=True)

            if time.time() - t > timeout:
                lsassy_logger.warning("File wasn't removed `{file_path}`", exc_info=True)

            lsassy_logger.debug("Unable to delete file `{}`. Retrying...".format(file_path))
            time.sleep(0.5)


    @staticmethod
    def exists(session: WinrmSession, file_path):
        # this is janky but if the filename appears in the ls it is there
        result = session.smb_session.execute_ps(f"dir {file_path}")[0]
        return ntpath.basename(file_path).lower() in result.lower() or os.path.basename(file_path).lower() in result.lower()

    def open(self, share, path, file, timeout=3):
        """open

        Open remote file and copy it to local tmpfile
        """

        t = time.time()
        while True:
            share = share.replace("$", ":")
            path = path.replace("\\", "/")
            try:
                full_remote_path = ntpath.join(share, path, file)
                self._fpath = full_remote_path
            except Exception:
                lsassy_logger.warning("Parsing error with '{}'".format(path), exc_info=True)
                return None

            try:
                self._session.fetch(full_remote_path, self.get_local_path())
            except WinRMError:
                lsassy_logger.debug("Unable to open file `{}`. Retrying...".format(full_remote_path))
            finally:
                if os.path.exists(self.get_local_path()) and WinrmFile.exists(self._session, full_remote_path):
                    lsassy_logger.debug(f"File {full_remote_path} created!")
                    self._opened = True
                    return self
            if time.time() - t > timeout:
                lsassy_logger.warning(f"File wasn't opened `{full_remote_path}`", exc_info=True)
                return None

            time.sleep(0.5)

            # I cant get those easily
            #self._fileInfo = self._session.smb_session.queryInfo(self._tid, self._fid)
            #self._endOfFile = self._fileInfo.fields["EndOfFile"]


    def read(self, size):
        """
        Read an amount of bytes on the 'remote' file - this reads from the local file with the content WHEN OPEN WAS CALLED -
        might be outdated if the file has been altered by the remote host in between open and read!
        If this becomes a problem every read should be prepended with a fetch!
        """
        if size == 0:
            return b""

        return self.file_mirror.read(size)

    def close(self):
        """
        Close handle to local file
        """
        if self._opened:
            self.file_mirror.close()
            self._opened = False

    def seek(self, offset, whence=0):
        """
        Seek a certain byte on the local file
        :param offset: Offset on the local file
        :param whence: 0 if absolute offset, 1 if relative offset, 2 if relative to the end of file
        """
        self.file_mirror.seek(offset, whence)

    def tell(self):
        """
        Get current offset
        :return: Current offset
        """
        return self.file_mirror.tell()

    def size(self):
        """
        Get remote file size
        :return: Remote file size
        """
        return os.path.getsize(self.get_local_path())

    def get_path(self):
        """
        Get remote file path
        :return: Remote file path (share, path)
        """
        return self._fpath

    def get_file_path(self):
        """
        Get relative file path
        :return:  Relative file path
        """
        return self._fpath

    def get_session(self):
        """
        Get current session
        :return: Current session
        """
        return self._session

    def get_local_path(self):
        return os.path.join(tempfile.gettempdir(), self.file_mirror.name)
