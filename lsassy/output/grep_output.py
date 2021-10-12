from lsassy.output import IOutput


class Output(IOutput):
    """
    Returns output in greppable format
    """
    def get_output(self):
        credentials = set()
        for cred in self._credentials:
            line = "{}\t{}\t{}\t{}\t{}\t{}\t{}".format(cred["ssp"], cred["domain"], cred["username"], cred["password"], cred["lmhash"], cred["nthash"], cred["sha1"])
            credentials.add(line)
        return "\n".join(cred for cred in credentials)