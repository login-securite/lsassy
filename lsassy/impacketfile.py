import logging
import time

from impacket.smb3structs import *


class ImpacketFile:
    """
    Remote file representation

    This class uses impacket method to create a file object with usual read methods so that it looks like a local
    file from another library point of view. Methods are
    - open
    - read
    - close
    - seek
    - tell
    """
    def __init__(self, session):
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
        self._buffer_data = {
            "offset": 0,
            "size": 0,
            "buffer": ""
        }

    def get_connection(self):
        """
        Method to access a private attribute
        :return: session instance
        """
        return self._session

    def _open_share(self):
        try:
            self._tid = self._session.smb_session.connectTree(self._share_name)
        except Exception as e:
            logging.warning("ConnectTree error with '{}'".format(self._share_name), exc_info=True)
            return None
        return self

    @staticmethod
    def create_file(session, share, path, file, content):
        path = path.replace("\\", "/")
        try:
            share, fpath = share, path + "/" + file
        except Exception as e:
            logging.warning("Parsing error with '{}'".format(path), exc_info=True)
            return None
        try:
            tid = session.smb_session.connectTree(share)
        except Exception as e:
            logging.warning("ConnectTree error with '{}'".format(share), exc_info=True)
            return None

        fid = None

        try:
            fid = session.smb_session._SMBConnection.create(tid, fpath, FILE_WRITE_DATA, FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE, FILE_OVERWRITE_IF, 0)
            finished = False
            MAX_FILE_WRITE = session.smb_session._SMBConnection._Connection['MaxWriteSize']
            rnd = 0
            while not finished:
                data = content[rnd*MAX_FILE_WRITE:(rnd+1)*MAX_FILE_WRITE]
                if len(data) == 0:
                    break
                session.smb_session._SMBConnection.write(tid, fid, data, rnd*MAX_FILE_WRITE, len(data))
                rnd += 1
        finally:
            if fid is not None:
                logging.debug("File {}{} created!".format(share, fpath))
                session.smb_session._SMBConnection.close(tid, fid)
                session.smb_session._SMBConnection.disconnectTree(tid)
                return True
        if tid is not None:
            session.smb_session._SMBConnection.disconnectTree(tid)
        return None

    @staticmethod
    def delete(session, file_path, timeout=5):
        t = time.time()
        while True:
            try:
                session.smb_session.deleteFile("C$", file_path)
                logging.debug("File {}{} deleted".format("C$", file_path))
                return True
            except BrokenPipeError:
                if time.time() - t > timeout:
                    logging.warning("File wasn't removed `{}{}`, connection lost".format("C$", file_path),
                                    exc_info=True)
                    return None
                logging.debug("Trying to reconnect ...")
                if session.login():
                    logging.success("Reconnected after unexpected disconnection for proper cleanup")
            except Exception as e:
                if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e) or "STATUS_NO_SUCH_FILE" in str(e):
                    return True
                if time.time() - t > timeout:
                    logging.warning("File wasn't removed `{}{}`".format("C$", file_path), exc_info=True)
                    return None
                logging.debug("Unable to delete file `{}{}`. Retrying...".format("C$", file_path))
                time.sleep(0.5)

    def open(self, share, path, file, timeout=3):
        """
        Open remote file
        :param share: Share location of the remote file
        :param path: Path of the remote file on provided share
        :param file: Remote filename
        :param timeout: Timeout if file access hangs
        :return: instance of this class
        """
        path = path.replace("\\", "/")
        try:
            self._share_name, self._fpath = share, path + "/" + file
        except Exception as e:
            logging.warning("Parsing error with '{}'".format(path), exc_info=True)
            return None

        if self._open_share() is None:
            return None

        t = time.time()
        while True:
            try:
                self._fid = self._session.smb_session.openFile(self._tid, self._fpath, desiredAccess=FILE_READ_DATA)
                logging.info("{} handle acquired".format(self._fpath))
                break
            except Exception as e:
                if time.time() - t > timeout:
                    logging.warning("Unable to open remote file {}".format( self._fpath), exc_info=True)
                    return None
                logging.debug("Unable to open remote file {}. Retrying...".format(self._fpath))
                time.sleep(0.5)

        self._fileInfo = self._session.smb_session.queryInfo(self._tid, self._fid)
        self._endOfFile = self._fileInfo.fields["EndOfFile"]
        self._opened = True
        return self

    def read(self, size):
        """
        Read an amount of bytes on the remote file

        This method uses some caching mechanisms to increase reading speed
        :param size: Number of bytes to read
        :return: Buffer containing file's content
        """
        if size == 0:
            return b''

        if (self._buffer_data["offset"] <= self._currentOffset <= self._buffer_data["offset"] + self._buffer_data[
            "size"]
                and self._buffer_data["offset"] + self._buffer_data["size"] > self._currentOffset + size):
            value = self._buffer_data["buffer"][
                    self._currentOffset - self._buffer_data["offset"]:self._currentOffset - self._buffer_data[
                        "offset"] + size]
        else:
            self._buffer_data["offset"] = self._currentOffset

            """
            If data size is too small, read self._buffer_min_size bytes and cache them
            """
            if size < self._buffer_min_size:
                value = self._session.smb_session.readFile(self._tid, self._fid, self._currentOffset, self._buffer_min_size)
                self._buffer_data["size"] = self._buffer_min_size
                self._total_read += self._buffer_min_size

            else:
                value = self._session.smb_session.readFile(self._tid, self._fid, self._currentOffset, size + self._buffer_min_size)
                while len(value) < size+self._buffer_min_size and self._currentOffset + len(value) < self._endOfFile:
                    value += self._session.smb_session.readFile(self._tid, self._fid, self._currentOffset + len(value), size + self._buffer_min_size - len(value))
                self._buffer_data["size"] = size + self._buffer_min_size
                self._total_read += size

            self._buffer_data["buffer"] = value

        self._currentOffset += size

        return value[:size]

    def close(self):
        """
        Close handle to remote file
        """
        if self._opened:
            self._session.smb_session.closeFile(self._tid, self._fid)
            self._session.smb_session.disconnectTree(self._tid)
            self._opened = False

    def seek(self, offset, whence=0):
        """
        Seek a certain byte on the remote file
        :param offset: Offset on the remote file
        :param whence: 0 if absolute offset, 1 if relative offset, 2 if relative to the end of file
        """
        if whence == 0:
            self._currentOffset = offset
        elif whence == 1:
            self._currentOffset += offset
        elif whence == 2:
            self._currentOffset = self._endOfFile - offset
        else:
            raise Exception('Seek function whence value must be between 0-2')

    def tell(self):
        """
        Get current offset
        :return: Current offset
        """
        return self._currentOffset

    def size(self):
        """
        Get remote file size
        :return: Remote file size
        """
        return self._endOfFile

    def get_path(self):
        """
        Get remote file path
        :return: Remote file path (share, path)
        """
        return self._share_name, self._fpath

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
