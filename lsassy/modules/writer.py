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
        def __init__(self, format="pretty", output_file=None, quiet=False):
            self.format = format
            self.output_file = output_file
            self.quiet = quiet

    def __init__(self, hostname, credentials, logger, options=Options()):
        self._hostname = hostname
        self._log = logger
        self._credentials = credentials
        self._format = options.format
        self._file = options.output_file
        self._quiet = options.quiet

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

    def get_output(self):
        output = ""

        if self._format == "json":
            json_output = {}
            for cred in self._credentials:
                ssp, domain, username, password, lmhash, nthash, shahash = cred

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
                    "nthash": nthash,
                    "shahash": shahash
                }
                if credential not in json_output[domain][username]:
                    json_output[domain][username].append(credential)
            output = json.dumps(json_output)
        elif self._format == "grep":
            credentials = set()
            for cred in self._credentials:
                credentials.add('\t'.join([Writer._decode(c) if c is not None else '' for c in cred]))
            output = "\n".join(cred for cred in credentials)
        elif self._format == "pretty":
            if len(self._credentials) == 0:
                self._log.warn('No credentials found')
                output = "No credentials"
            else:
                max_size = max(len(c[1]) + len(c[2]) for c in self._credentials)
                credentials = []
                for cred in self._credentials:
                    ssp, domain, username, password, lmhash, nthash, shahash = cred
                    domain = Writer._decode(domain)
                    username = Writer._decode(username)
                    password = Writer._decode(password)
                    if password is None:
                        password = ("[LM]"+lmhash+":") if lmhash is not None else ""
                        password+= ("[NT]"+nthash+":") if nthash is not None else ""
                        password+= ("[SHA1]"+shahash) if shahash is not None else ""
                        #password = ':'.join(h for h in [lmhash, nthash,shahash] if h is not None)
                    if [domain, username, password] not in credentials:
                        credentials.append([domain, username, password])
                        output += self._log.success(
                            "{}\\{}{}{}".format(
                                domain,
                                username,
                                " " * (max_size - len(domain) - len(username) + 2),
                                Logger.highlight(password)), output=False
                        )

        elif self._format == "none":
            pass
        else:
            return RetCode(ERROR_OUTPUT_FORMAT_INVALID, Exception("Output format {} is not valid".format(self._format)))

        return output

    def write(self):
        output = self.get_output()
        if isinstance(output, int):
            return output

        if not self._quiet:
            print(output, end="\n")
        if self._file:
            ret = self.write_file(output)
            if not ret.success():
                lsassy_warn(self._log, ret)
            else:
                self._log.info("Credentials saved to {}".format(self._file))

        return RetCode(ERROR_SUCCESS)

    def write_file(self, output):
        path = Path(self._file).parent
        if not os.path.isdir(path):
            return RetCode(ERROR_OUTPUT_DIR_NOT_EXIST, Exception("Directory {} does not exist".format(path)))

        with open(self._file, 'a+') as f:
            f.write(output + "\n")
        return RetCode(ERROR_SUCCESS)
