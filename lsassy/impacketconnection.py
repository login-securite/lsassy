# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import re
import sys
import time
from socket import getaddrinfo, gaierror

from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SMBConnection, SessionError

from lsassy.logger import Logger
from lsassy.defines import *


class ImpacketConnection:
    def __init__(self, hostname, domain_name, username, password, hashes):
        self._log = Logger()
        self.hostname = hostname
        self.domain_name = domain_name
        self.username = username
        self.password = password
        self.lmhash, self.nthash = "", ""
        if not password and hashes:
            if ":" in hashes:
                self.lmhash, self.nthash = hashes.split(":")
            else:
                self.lmhash, self.nthash = 'aad3b435b51404eeaad3b435b51404ee', hashes

        self.conn = None

    def get_logger(self):
        return self._log

    def set_logger(self, logger):
        self._log = logger

    def login(self):
        try:
            ip = list({addr[-1][0] for addr in getaddrinfo(self.hostname, 0, 0, 0, 0)})[0]
        except gaierror as e:
            return RetCode(ERROR_DNS_ERROR, e)

        try:
            conn = SMBConnection(ip, ip)
        except Exception as e:
            return RetCode(ERROR_CONNECTION_ERROR, e)

        username = self.username.split("@")[0]
        self._log.debug("Authenticating against {}".format(ip))
        try:
            conn.login(username, self.password, domain=self.domain_name, lmhash=self.lmhash, nthash=self.nthash, ntlmFallback=True)
        except SessionError as e:
            self._log.debug("Provided credentials : {}\\{}:{}".format(self.domain_name, username, self.password))
            return RetCode(ERROR_LOGIN_FAILURE, e)
        except Exception as e:
            return RetCode(ERROR_UNDEFINED, e)
        self.conn = conn
        return RetCode(ERROR_SUCCESS)

    def connectTree(self, share_name):
        return self.conn.connectTree(share_name)

    def openFile(self, tid, fpath, timeout=10):
        self._log.debug("Opening file {}".format(fpath))

        start = time.time()
        try:
            timeout = float(timeout)
        except ValueError as e:
            self._log.debug("Timeout value \"{}\" is not valid. Timeout set to 10".format(str(timeout)))
            timeout = 10

        while True:
            try:
                fid = self.conn.openFile(tid, fpath, desiredAccess=FILE_READ_DATA)
                self._log.debug("File {} opened".format(fpath))
                return fid
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0 or str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                    # Output not finished, let's wait
                    if time.time() - start > timeout:
                        raise(Exception(e))
                    time.sleep(1)
                else:
                    raise Exception(e)

    def queryInfo(self, tid, fid):
        while True:
            try:
                info = self.conn.queryInfo(tid, fid)
                return info
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    # Output not finished, let's wait
                    time.sleep(2)
                else:
                    raise Exception(e)

    def getFile(self, share_name, path_name, callback):
        while True:
            try:
                self.conn.getFile(share_name, path_name, callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    # Output not finished, let's wait
                    time.sleep(2)
                else:
                    raise Exception(e)

    def deleteFile(self, share_name, path_name):
        while True:
            try:
                self.conn.deleteFile(share_name, path_name)
                self._log.debug("File {} deleted".format(path_name))
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    time.sleep(2)
                else:
                    raise Exception(e)

    def putFile(self, share_name, path_name, callback):
        try:
            self.conn.putFile(share_name, path_name, callback)
            self._log.debug("File {} uploaded".format(path_name))
        except Exception as e:
            raise Exception("An error occured while uploading %s on %s share : %s" % (path_name, share_name, e))

    def readFile(self, tid, fid, offset, size):
        return self.conn.readFile(tid, fid, offset, size, singleCall=False)

    def closeFile(self, tid, fid):
        return self.conn.closeFile(tid, fid)

    def isadmin(self):
        try:
            self.connectTree("C$")
            return RetCode(ERROR_SUCCESS)
        except Exception as e:
            return RetCode(ERROR_ACCESS_DENIED, e)

    def close(self):
        self.conn.close()

    def clean(self):
        try:
            self.close()
            return RetCode(ERROR_SUCCESS)
        except Exception as e:
            return RetCode(ERROR_CONNECTION_CLEANING, e)
