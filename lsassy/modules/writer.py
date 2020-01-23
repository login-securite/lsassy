# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import json
from pathlib import Path

from lsassy.utils.utils import *
from lsassy.modules.logger import Logger


class Writer:
    class Options:
        def __init__(self, format="pretty", output_file=None):
            self.format = format
            self.output_file = output_file

    def __init__(self, hostname, credentials, logger, options=Options()):
        self._hostname = hostname
        self._log = logger
        self._credentials = credentials
        self._format = options.format
        self._file = options.output_file

    @staticmethod
    def _decode(data):
        """
        Ugly trick because of mixed content coming back from pypykatz
        Can be either string, bytes, None
        """
        try:
            return data.decode('utf-8', 'backslashreplace')
        except:
            return data

    def write(self):
        if self._file:
            ret = self.write_file()
            if not ret.success():
                lsassy_warn(self._log, ret)
            else:
                self._log.info("Credentials saved to {}".format(self._file))

        if self._format == "json":
            json_output = {}
            for cred in self._credentials:
                ssp, domain, username, password, lmhash, nthash = cred

                domain = Writer._decode(domain)
                username = Writer._decode(username)
                password = Writer._decode(password)

                if domain not in json_output:
                    json_output[domain] = {}
                if username not in json_output[domain]:
                    json_output[domain][username] = []
                credential = {
                    "password": password,
                    "lmhash": lmhash,
                    "nthash": nthash
                }
                if credential not in json_output[domain][username]:
                    json_output[domain][username].append(credential)
            print(json.dumps(json_output), end='')
        elif self._format == "grep":
            credentials = set()
            for cred in self._credentials:
                credentials.add('\t'.join([Writer._decode(c) if c is not None else '' for c in cred]))
            for cred in credentials:
                print(cred)
        elif self._format == "pretty":
            if len(self._credentials) == 0:
                self._log.warn('No credentials found')
                return RetCode(ERROR_NO_CREDENTIAL_FOUND)

            max_size = max(len(c[1]) + len(c[2]) for c in self._credentials)
            credentials = []
            for cred in self._credentials:
                ssp, domain, username, password, lmhash, nthash = cred
                domain = Writer._decode(domain)
                username = Writer._decode(username)
                password = Writer._decode(password)
                if password is None:
                    password = ':'.join(h for h in [lmhash, nthash] if h is not None)
                if [domain, username, password] not in credentials:
                    credentials.append([domain, username, password])
                    self._log.success(
                        "{}\\{}{}{}".format(
                            domain,
                            username,
                            " " * (max_size - len(domain) - len(username) + 2),
                            Logger.highlight(password))
                    )

        elif self._format == "none":
            pass
        else:
            return RetCode(ERROR_OUTPUT_FORMAT_INVALID, Exception("Output format {} is not valid".format(self._format)))

        return RetCode(ERROR_SUCCESS)

    def write_file(self):
        path = Path(self._file).parent
        if not os.path.isdir(path):
            return RetCode(ERROR_OUTPUT_DIR_NOT_EXIST, Exception("Directory {} does not exist".format(path)))

        with open(self._file, 'a+') as f:
            credentials = []
            for cred in self._credentials:
                ssp, domain, username, password, lmhash, nthash = cred
                domain = Writer._decode(domain)
                username = Writer._decode(username)
                password = Writer._decode(password)
                if [domain, username, password, lmhash, nthash] not in credentials:
                    credentials.append([domain, username, password, lmhash, nthash])
                    f.write(
                        "{}\t{}\\{}\t{}\t{}\n".format(
                            self._hostname,
                            domain,
                            username,
                            password if password is not None else "",
                            (lmhash if lmhash is not None else "") + ":" + nthash if nthash is not None else "" if lmhash or nthash else ""
                        )
                    )
        return RetCode(ERROR_SUCCESS)
