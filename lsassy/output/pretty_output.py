from lsassy import logger
from lsassy.output import IOutput


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
            credentials = []
            for cred in self._credentials:
                type = "PWD"
                if cred["password"] is None:
                    cred["password"] = ':'.join(h for h in [cred["lmhash"], cred["nthash"]] if h is not None)
                    type = "NT"
                if [cred["domain"], cred["username"], cred["password"]] not in credentials:
                    credentials.append([cred["domain"], cred["username"], cred["password"]])
                    output.append(
                        "{}\\{}{}{}{}{}".format(
                            cred["domain"],
                            cred["username"],
                            " " * (max_size - len(cred["domain"]) - len(cred["username"]) + 2),
                            logger.highlight("[{}] ".format(type)),
                            logger.highlight(cred["password"]),
                            " | {}".format(logger.highlight("[{}] {}".format("SHA1", cred["sha1"]))) if cred["sha1"] else "")
                    )
        return "\n".join(output)
