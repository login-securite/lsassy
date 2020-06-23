import logging
import re
import time

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

        try:
            self._tid = self._session.smb_session.connectTree(self._share_name)
        except Exception as e:
            logging.warning("ConnectTree error with '{}'".format(self._share_name), exc_info=True)
            return None
        t = time.time()
        while True:
            try:
                self._fid = self._session.smb_session.openFile(self._tid, self._fpath)
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
                self._buffer_data["size"] = size + self._buffer_min_size
                self._total_read += size

            self._buffer_data["buffer"] = value

        self._currentOffset += size

        return value[:size]

    def close(self):
        """
        Close handle to remote file
        """
        self._session.smb_session.closeFile(self._tid, self._fid)
        self._session.smb_session.disconnectTree(self._tid)

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

    def get_session(self):
        """
        Get current session
        :return: Current session
        """
        return self._session
