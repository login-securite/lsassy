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
        table.add_column("Sha1")
        credentials = []
        for cred in self._credentials:
            if [cred["domain"], cred["username"], cred["password"], cred["lmhash"], cred["nthash"], cred["sha1"]] not in credentials:
                credentials.append([cred["domain"], cred["username"], cred["password"], cred["lmhash"], cred["nthash"], cred["sha1"]])
                table.add_row(
                    "{}{}".format(
                        "{}\\".format(cred["domain"]) if cred["domain"] is not None else "",
                        cred["username"] if cred["username"] is not None else ""
                    ),
                    cred["password"] if cred["password"] is not None else "",
                    ':'.join(h for h in [cred["lmhash"], cred["nthash"]] if h is not None),
                    cred["sha1"] if cred["sha1"] is not None else "")
        console = Console()
        console.print(table, no_wrap=True)
        return ""
