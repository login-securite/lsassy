# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import re

from lsassy.utils.defines import *


class ImpacketFile:
    def __init__(self, connection, log):
        self._log = log
        self._conn = connection
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
        return self._conn

    def open(self, path, timeout=3):
        try:
            share_name, fpath = self._parse_path(path)
        except Exception as e:
            return RetCode(ERROR_PATH_FILE, e)

        self._fpath = fpath
        try:
            self._tid = self._conn.connectTree(share_name)
        except Exception as e:
            self.clean()
            return RetCode(ERROR_SHARE, e)
        try:
            self._fid = self._conn.openFile(self._tid, self._fpath, timeout=timeout)
        except Exception as e:
            self.clean()
            return RetCode(ERROR_FILE, e)
        self._fileInfo = self._conn.queryInfo(self._tid, self._fid)
        self._endOfFile = self._fileInfo.fields["EndOfFile"]
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clean()

    def read(self, size):
        if size == 0:
            return b''

        if (self._buffer_data["offset"] <= self._currentOffset <= self._buffer_data["offset"] + self._buffer_data["size"]
                and self._buffer_data["offset"] + self._buffer_data["size"] > self._currentOffset + size):
            value = self._buffer_data["buffer"][self._currentOffset - self._buffer_data["offset"]:self._currentOffset - self._buffer_data["offset"] + size]
        else:
            self._buffer_data["offset"] = self._currentOffset

            """
            If data size is too small, read self._buffer_min_size bytes and cache them
            """
            if size < self._buffer_min_size:
                value = self._conn.readFile(self._tid, self._fid, self._currentOffset, self._buffer_min_size)
                self._buffer_data["size"] = self._buffer_min_size
                self._total_read += self._buffer_min_size
                
            else:
                value = self._conn.readFile(self._tid, self._fid, self._currentOffset, size + self._buffer_min_size)
                self._buffer_data["size"] = size + self._buffer_min_size
                self._total_read += size
            
            self._buffer_data["buffer"] = value

        self._currentOffset += size

        return value[:size]

    def close(self):
        self._log.debug("Closing Impacket file \"{}\"".format(self._fpath))
        self._conn.closeFile(self._tid, self._fid)
        self._conn.disconnectTree(self._tid)

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

    def clean(self):
        try:
            self.close()
        except Exception as e:
            pass

    @staticmethod
    def _parse_path(fpath):
        pattern = re.compile(r"^(?P<share_name>[^/]+)(?P<filePath>/(?:[^/]*/)*[^/]+)$")
        matches = pattern.search(fpath)
        if matches is None:
            raise Exception("{} is not valid. Expected format : shareName/path/to/dump (c$/Windows/Temp/lsass.dmp)".format(fpath))
        return matches.groups()
