# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import json

from lsassy.logger import Logger
from lsassy.defines import *


class Writer:
    class Options:
        format = "pretty"

    def __init__(self, credentials, logger, options=Options):
        self._log = logger
        self._credentials = credentials
        self._format = options.format

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
        if self._format == "json":
            json_output = {}
            for cred in self._credentials:
                ssp, domain, username, password, lhmash, nthash = cred

                domain = Writer._decode(domain)
                username = Writer._decode(username)
                password = Writer._decode(password)

                if domain not in json_output:
                    json_output[domain] = {}
                if username not in json_output[domain]:
                    json_output[domain][username] = []
                credential = {
                    "password": password,
                    "lmhash": lhmash,
                    "nthash": nthash
                }
                if credential not in json_output[domain][username]:
                    json_output[domain][username].append(credential)
            print(json.dumps(json_output), end='')
        elif self._format == "grep":
            credentials = set()
            for cred in self._credentials:
                credentials.add(':'.join([Writer._decode(c) if c is not None else '' for c in cred]))
            for cred in credentials:
                print(cred)
        elif self._format == "pretty":
            if len(self._credentials) == 0:
                self._log.warn('No credentials found')
                return RetCode(ERROR_NO_CREDENTIAL_FOUND)

            max_size = max(len(c[1]) + len(c[2]) for c in self._credentials)
            credentials = []
            for cred in self._credentials:
                ssp, domain, username, password, lhmash, nthash = cred
                domain = Writer._decode(domain)
                username = Writer._decode(username)
                password = Writer._decode(password)
                if password is None:
                    password = ':'.join(h for h in [lhmash, nthash] if h is not None)
                if [domain, username, password] not in credentials:
                    credentials.append([domain, username, password])
                    self._log.success(
                        "{}\\{}{}{}".format(
                            domain,
                            username,
                            " " * (max_size - len(domain) - len(username) + 2),
                            Logger.highlight(password)),
                        force=True
                    )

        else:
            return RetCode(ERROR_OUTPUT_FORMAT_INVALID, Exception("Output format {} is not valid".format(self._format)))

        return RetCode(ERROR_SUCCESS)
