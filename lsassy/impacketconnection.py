# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import time, re
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import FILE_READ_DATA, SMB2_DIALECT_21, SMB2_DIALECT_30
from socket import getaddrinfo, gaierror
from lsassy.log import Logger


class ImpacketConnection:
    def __init__(self, conn=None, debug=False):
        self._log = Logger(debug)
        self.conn = conn
        self._log.debug("Preferred dialect is SMBv2")

    @staticmethod
    def from_args(arg, debug=False):
        pattern = re.compile(r"^(?:(?P<domainName>[a-zA-Z0-9._-]+)/)?(?P<userName>[^:/]+)(?::(?P<password>.*))?@(?P<hostName>[a-zA-Z0-9.-]+):/(?P<shareName>[^/]+)(?P<filePath>/(?:[^/]*/)*[^/]+)$")
        matches = pattern.search(arg.target)
        if matches is None:
            raise Exception("{} is not valid. Expected format : [domain/]username[:password]@host:/shareName/path/to/file".format(arg.target))
        domainName, userName, password, hostName, shareName, filePath = matches.groups()
        if matches.group("domainName") is None:
            domainName = "."
        if matches.group("password") is None:
            import getpass
            password = getpass.getpass(prompt='Password: ')
        return ImpacketConnection(debug=debug).login(hostName, userName, password, domainName), shareName, filePath


    def login(self, ip, username, password, domain):
        try:
            ip = list({addr[-1][0] for addr in getaddrinfo(ip, 0, 0, 0, 0)})[0]
        except gaierror:
            raise Exception("No DNS found to resolve %s.\n"
                            "Please make sure that your DNS settings can resolve %s" % (ip, ip))
        conn = SMBConnection(ip, ip)
        username = username.split("@")[0]
        self._log.debug("Authenticating against {}".format(ip))
        try:
            if re.match(r"^[0-9a-f]{32}$", password, re.IGNORECASE):
                conn.login(username, password, domain=domain, nthash=password, ntlmFallback=True)
                self._log.success("Authenticated via NT hash")
            else:
                conn.login(username, password, domain)
                self._log.success("Authenticated via clear text password")
        except SessionError as e:
            self._log.error("Session Error")
            self._log.debug("Provided credentials : {}\\{}:{}".format(domain, username, password))
            raise SessionError(e)
        except Exception as e:
            raise Exception("Unknown error : {}".format(e))
        self.conn = conn
        return self

    def connectTree(self, shareName):
        return self.conn._SMBConnection.connectTree(shareName)

    def openFile(self, tid, fpath):
        while True:
            try:
                fid = self.conn.openFile(tid, fpath, desiredAccess=FILE_READ_DATA)
                self._log.debug("File {} opened".format(fpath))
                return fid
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    # Output not finished, let's wait
                    time.sleep(2)
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
        

    def getFile(self, shareName, pathName, callback):
        while True:
            try:
                self.conn.getFile(shareName, pathName, callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    # Output not finished, let's wait
                    time.sleep(2)
                else:
                    raise Exception(e)

    def deleteFile(self, shareName, pathName):
        while True:
            try:
                self.conn.deleteFile(shareName, pathName)
                self._log.debug("File {} deleted".format(pathName))
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    time.sleep(2)
                else:
                    raise Exception(e)

    def putFile(self, shareName, pathName, callback):
        try:
            self.conn.putFile(shareName, pathName, callback)
            self._log.debug("File {} uploaded".format(pathName))
        except Exception as e:
            raise Exception("An error occured while uploading %s on %s share : %s" % (pathName, shareName, e))

    def readFile(self, tid, fid, offset, size):
        return self.conn.readFile(tid, fid, offset, size, singleCall=False)

    def close(self):
        self.conn.close()
