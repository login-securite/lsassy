import json

from lsassy.output import IOutput


class Output(IOutput):
    """
    Return output in json format
    """
    def get_output(self):
        json_output = {}
        for cred in self._credentials:
            if cred["domain"] not in json_output:
                json_output[cred["domain"]] = {}
            if cred["username"] not in json_output[cred["domain"]]:
                json_output[cred["domain"]][cred["username"]] = []
            credential = {
                "password": cred["password"],
                "lmhash": cred["lmhash"],
                "nthash": cred["nthash"],
                "sha1": cred["sha1"]
            }
            if credential not in json_output[cred["domain"]][cred["username"]]:
                json_output[cred["domain"]][cred["username"]].append(credential)
        return json.dumps(json_output)
