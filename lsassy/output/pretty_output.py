import logging

from lsassy.output.ioutput import IOutput
from lsassy import logger


class Output(IOutput):
    """
    Return output in pretty colorful format
    """
    def get_output(self):
        output = []
        if len(self._credentials) == 0:
            return "No credentials found"
        else:
            max_size = max(len(c["domain"]) + len(c["username"]) for c in self._credentials)
            max_src_size = max(len(c["source"]) for c in self._credentials)
            credentials = []
            for cred in self._credentials:
                if cred["password"] is None:
                    cred["password"] = ':'.join(h for h in [cred["lmhash"], cred["nthash"]] if h is not None)
                if [cred["domain"], cred["username"], cred["password"]] not in credentials:
                    credentials.append([cred["domain"], cred["username"], cred["password"]])
                    o = "[{}]{}".format(cred["source"], " " * (max_src_size - len(cred["source"]) + 2))
                    if cred["domain"]:
                        o += "{}\\".format(cred["domain"])
                    o += "{}{}{}".format(
                        cred["username"],
                        " " * (max_size - len(cred["domain"]) - len(cred["username"]) + 2),
                        logger.highlight(cred["password"])
                    )
                    if cred["data"]:
                        o += " ({})".format(", ".join([k + ": " + v for k, v in cred["data"].items()]))
                    output.append(o)
        return "\n".join(output)

    def get_dpapi_output(self):
        output = []
        if len(self._credentials) == 0:
            return "No credentials found"
        else:
            credentials = []
            for cred in self._credentials:
                if [cred["password"], cred["username"], cred["url"]] not in credentials:
                    credentials.append([cred["password"], cred["username"], cred["url"]])
                    output.append("{} ({} for {})".format(logger.highlight(cred["password"]), cred["username"], cred["url"]))
        return "\n".join(output)
