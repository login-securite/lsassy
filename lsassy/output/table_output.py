from rich import box
from rich.console import Console
from rich.table import Table

from lsassy.output import IOutput


class Output(IOutput):
    """
    Return output in pretty colorful format
    """
    def get_output(self):
        table = Table(
            show_header=True,
            header_style="bold blue",
            border_style="grey35",
            caption_style="",
            caption_justify="left",
            box=box.SQUARE
        )

        table.add_column("Username")
        table.add_column("Password")
        table.add_column("Hash")
        table.add_column("TGT")
        table.add_column("Sha1")
        table.add_column("Masterkeys")
        credentials = []
        for cred in self._credentials:
            if [cred["domain"], cred["username"], cred["password"], cred["lmhash"], cred["nthash"], cred["sha1"], cred["ticket"],  cred["masterkey"]] not in credentials:
                credentials.append([cred["domain"], cred["username"], cred["password"], cred["lmhash"], cred["nthash"], cred["sha1"], cred["ticket"],  cred["masterkey"]])
                table.add_row(
                    "{}{}".format(
                        "{}\\".format(cred["domain"]) if cred["domain"] is not None and cred["domain"] != "" else "",
                        cred["username"] if cred["username"] is not None and cred["username"] != "" else ""
                    ),
                    cred["password"] if cred["password"] is not None else "",
                    ':'.join(h for h in [cred["lmhash"], cred["nthash"]] if h is not None),

                    cred["sha1"] if cred["sha1"] is not None else "",
                    "{} - {}".format(cred["ticket"]["domain"], cred["ticket"]["endtime"].strftime("%Y-%m-%d %H:%M")) if cred["ticket"] is not None else "",
                    "{}".format(cred["masterkey"]) if cred["masterkey"] is not None else "")
        return table

