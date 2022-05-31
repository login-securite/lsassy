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
                cred_type = "PWD"
                if cred["password"] is None:
                    if cred["ticket"] is not None:
                        cred["password"] = "Domain: {} - End time: {} ({})".format(cred["ticket"]["domain"], cred["ticket"]["endtime"].strftime("%Y-%m-%d %H:%M"), cred['ticket']['file'])
                        cred_type = "TGT"
                    elif cred["masterkey"] is not None:
                        cred["password"] = "{}".format(cred["masterkey"])
                        cred_type = "DPAPI Masterkey"
                    else:
                        cred["password"] = ':'.join(h for h in [cred["lmhash"], cred["nthash"]] if h is not None)
                        cred_type = "NT"
                if [cred["domain"], cred["username"], cred["password"]] not in credentials:
                    credentials.append([cred["domain"], cred["username"], cred["password"]])
                    output.append(
                        "{}{}{}{}{}{}".format(
                            ('{}\\'.format(cred["domain"]) if cred["domain"] is not None and cred["domain"] != "" else " "),
                            cred["username"],
                            " " * (max_size - len(cred["domain"]) - len(cred["username"]) + 2),
                            logger.highlight("[{}] ".format(cred_type)),
                            logger.highlight(cred["password"]),
                            " | {}".format(logger.highlight("[{}] {}".format("SHA1", cred["sha1"]))) if cred["sha1"] else "")
                    )
        return "\n".join(output)
