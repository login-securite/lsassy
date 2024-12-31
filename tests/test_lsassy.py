import unittest
from argparse import Namespace

from lsassy.core import ThreadPool
from lsassy.dumper import Dumper
from lsassy.parser import Parser
from lsassy.session import Session
from lsassy.writer import Writer

USERNAME = "pixis"
PASSWORD = "P4ssw0rd"
HOSTNAME = "127.0.0.1"


class TestCLI(unittest.TestCase):
    def test_threads(self):
        MAX_THREADS = 1337
        args = Namespace(
            dump_method="comsvcs",
            dump_path=None,
            dump_name=None,
            exec="smb",
            no_powershell=False,
            copy=False,
            options=None,
            timeout=10,
            time_between_commands=1,
            parse_only=False,
            dump_only=False,
            keep_dump=False,
            username=USERNAME,
            password=PASSWORD,
            domain="RANDOM",
            port=445,
            no_pass=False,
            hashes=None,
            kerberos=False,
            dc_ip=None,
            aesKey=None,
            kerberos_dir=None,
            masterkeys_file=None,
            outfile=None,
            format="pretty",
            file_format=None,
            no_color=False,
            users=False,
            no_tickets=False,
            masterkeys=False,
            v=2,
            threads=MAX_THREADS,
            quiet=False,
            target=[HOSTNAME],
        )
        l = ThreadPool("HACKNDO", args)
        self.assertEqual(
            l.max_threads, MAX_THREADS, "Max threads not taken into account"
        )


class TestDumper(unittest.TestCase):
    def test_list_dump_methods(self):
        self.assertEqual(
            Dumper.list_dump_methods(),
            [
                "comsvcs",
                "comsvcs_stealth",
                "dllinject",
                "dumpert",
                "dumpertdll",
                "edrsandblast",
                "mirrordump",
                "mirrordump_embedded",
                "nanodump",
                "nanodump_ssp_embedded",
                "ppldump",
                "ppldump_embedded",
                "procdump",
                "procdump_embedded",
                "rawrpc",
                "rawrpc_embedded",
                "rdrleakdiag",
                "silentprocessexit",
                "sqldumper",
                "wer",
            ],
            "Error in list_dump_methods",
        )

    def test_load(self):
        dumper = Dumper(None, 0, 0)
        for dump_method in Dumper.list_dump_methods():
            self.assertIsNotNone(dumper.load(dump_method))

    def test_dump_method_get_commands(self):
        dumper = Dumper(None, 0, 0)
        for dump_method in Dumper.list_dump_methods():
            try:
                dumper.load(dump_method).get_commands()
            except NotImplemented:
                self.fail(
                    "get_commands() raised NotImplemented for {}".format(dump_method)
                )


class TestWorkflow(unittest.TestCase):
    def test_workflow(self):
        session = Session()
        session.get_session(
            address=HOSTNAME,
            target_ip=HOSTNAME,
            port=445,
            username=USERNAME,
            password=PASSWORD,
        )
        self.assertIsNotNone(session.smb_session)

        dumper = Dumper(session, 5, 1).load("comsvcs")
        self.assertIsNotNone(dumper)

        file = dumper.dump(exec_methods=["smb"])
        self.assertIsNotNone(file)

        credentials, tickets, masterkeys = Parser(HOSTNAME, file).parse()

        file.close()
        self.assertTrue(len(credentials) > 0)

        writer = Writer(credentials, tickets, masterkeys)
        writer.write(file_format="pretty", out_format="pretty")


class TestExecMethods(unittest.TestCase):
    def setUp(self) -> None:
        self.session = Session()
        self.session.get_session(
            address=HOSTNAME,
            target_ip=HOSTNAME,
            port=445,
            username=USERNAME,
            password=PASSWORD,
        )

    def dump_lsass(self, exec):
        dumper = Dumper(self.session, 5, 1).load("comsvcs")
        file = dumper.dump(exec_methods=[exec])
        self.assertIsNotNone(file)
        file.close()

    def test_smb(self):
        self.dump_lsass("smb")

    def test_task(self):
        self.dump_lsass("task")

    def test_smb_stealth(self):
        self.dump_lsass("smb_stealth")

    """
    @TODO To fix
    def test_mmc(self):
        self.dump_lsass("mmc")

    @TODO To fix
    def test_wmi(self):
        self.dump_lsass("wmi")
    """


class TestDumpMethods(unittest.TestCase):
    def setUp(self) -> None:
        self.session = Session()
        self.session.get_session(
            address=HOSTNAME,
            target_ip=HOSTNAME,
            port=445,
            username=USERNAME,
            password=PASSWORD,
        )

    def dump_lsass(self, method):
        dumper = Dumper(self.session, 5, 1).load(method)
        file = dumper.dump(exec_methods=["smb"])
        self.assertIsNotNone(file)
        file.close()

    def test_comsvcs(self):
        self.dump_lsass("comsvcs")

    def test_comsvcs_stealth(self):
        self.dump_lsass("comsvcs_stealth")

    def test_mirrordump_embedded(self):
        self.dump_lsass("mirrordump_embedded")

    def test_nanodump_ssp_embedded(self):
        self.dump_lsass("nanodump_ssp_embedded")

    """
    def test_ppldump_embedded(self):
        self.dump_lsass("ppldump_embedded")
    """

    def test_procdump_embedded(self):
        self.dump_lsass("procdump_embedded")

    def test_rawrpc_embedded(self):
        self.dump_lsass("rawrpc_embedded")

    def test_rdrleakdiag(self):
        self.dump_lsass("rdrleakdiag")

    def test_wer(self):
        self.dump_lsass("wer")


class TestWriter(unittest.TestCase):
    """
    Test write output and file
    """

    def setUp(self) -> None:
        session = Session()
        session.get_session(
            address=HOSTNAME,
            target_ip=HOSTNAME,
            port=445,
            username=USERNAME,
            password=PASSWORD,
        )
        self.assertIsNotNone(session.smb_session)

        dumper = Dumper(session, 5, 1).load("comsvcs")
        self.assertIsNotNone(dumper)

        file = dumper.dump(exec_methods=["smb"])
        self.assertIsNotNone(file)

        credentials, tickets, masterkeys = Parser(HOSTNAME, file).parse()

        file.close()
        self.assertTrue(len(credentials) > 0)

        self.writer = Writer(credentials, tickets, masterkeys)

    def test_pretty(self):
        self.assertTrue("[NT]" in self.writer.get_output(out_format="pretty"))

    def test_json(self):
        self.assertTrue('"nthash"' in self.writer.get_output(out_format="json"))

    def test_table(self):
        self.assertTrue("Username" in self.writer.get_output(out_format="table"))

    def test_grep(self):
        self.assertTrue("\tNone\t" in self.writer.get_output(out_format="grep"))
