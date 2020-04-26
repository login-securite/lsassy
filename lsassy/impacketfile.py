import logging
import re
import time

class ImpacketFile:
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
        return self._session

    def open(self, share, path, file, timeout=3):
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
        self._session.smb_session.closeFile(self._tid, self._fid)
        self._session.smb_session.disconnectTree(self._tid)

    def seek(self, offset, whence=0):
        if whence == 0:
            self._currentOffset = offset
        elif whence == 1:
            self._currentOffset += offset
        elif whence == 2:
            self._currentOffset = self._endOfFile - offset
        else:
            raise Exception('Seek function whence value must be between 0-2')

    def tell(self):
        return self._currentOffset

    def size(self):
        return self._endOfFile

    def get_path(self):
        return self._share_name, self._fpath

    def get_session(self):
        return self._session
