import logging

from lsassy.output.ioutput import IOutput
from lsassy import logger


class Output(IOutput):
    def get_output(self):
        output = []
        if len(self._credentials) == 0:
            return "No credentials found"
        else:
            max_size = max(len(c["domain"]) + len(c["username"]) for c in self._credentials)
            credentials = []
            for cred in self._credentials:
                if cred["password"] is None:
                    cred["password"] = ':'.join(h for h in [cred["lmhash"], cred["nthash"]] if h is not None)
                if [cred["domain"], cred["username"], cred["password"]] not in credentials:
                    credentials.append([cred["domain"], cred["username"], cred["password"]])
                    output.append(
                        "{}\\{}{}{}".format(
                            cred["domain"],
                            cred["username"],
                            " " * (max_size - len(cred["domain"]) - len(cred["username"]) + 2),
                            logger.highlight(cred["password"]))
                    )
        return "\n".join(output)
