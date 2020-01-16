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

from lsassy.log import Logger
from lsassy.defines import *


class ImpacketConnection:
    def __init__(self, conn=None, log=None):
        self._log = log if log is not None else Logger()
        self.hostname = ""
        self.username = ""
        self.domain_name = ""
        self.password = ""
        self.lmhash = ""
        self.nthash = ""
        self.conn = conn

    @staticmethod
    def from_args(arg, log):
        pattern = re.compile(r"^(?:(?P<domain_name>[a-zA-Z0-9._-]+)/)?(?P<username>[^:/]+)(?::(?P<password>.*))?@(?P<hostname>[a-zA-Z0-9.-]+)$")
        matches = pattern.search(arg.target)
        if matches is None:
            log.warn("{} is not valid. Expected format : [domain/]username[:password]@host".format(arg.target))
            return RetCode(ERROR_INVALID_FORMAT)
        domain_name, username, password, hostname = matches.groups()
        if matches.group("domain_name") is None:
            domain_name = "."
        if matches.group("password") is None and arg.hashes is None:
            import getpass
            password = getpass.getpass(prompt='Password: ')

        if arg.hashes is not None:
            if ':' in arg.hashes:
                lmhash, nthash = arg.hashes.split(':')
            else:
                lmhash = 'aad3b435b51404eeaad3b435b51404ee'
                nthash = arg.hashes
        else:
            lmhash = ''
            nthash = ''
        return ImpacketConnection(log=log).login(hostname, domain_name, username, password, lmhash, nthash)

    def login(self, ip, domain_name, username, password, lmhash, nthash):
        try:
            ip = list({addr[-1][0] for addr in getaddrinfo(ip, 0, 0, 0, 0)})[0]
        except gaierror as e:
            return RetCode(ERROR_DNS_ERROR, e)

        self.hostname = ip
        self.domain_name = domain_name
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash

        try:
            conn = SMBConnection(ip, ip)
        except Exception as e:
            return RetCode(ERROR_CONNEXION_ERROR, e)

        username = username.split("@")[0]
        self._log.debug("Authenticating against {}".format(ip))
        try:
            conn.login(username, password, domain=domain_name, lmhash=lmhash, nthash=nthash, ntlmFallback=True)
            self._log.success("Authenticated")
        except SessionError as e:
            self._log.debug("Provided credentials : {}\\{}:{}".format(domain_name, username, password))
            return RetCode(ERROR_LOGIN_FAILURE, e)
        except Exception as e:
            return RetCode(ERROR_UNDEFINED, e)
        self.conn = conn
        return self

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
