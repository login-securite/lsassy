#!/usr/bin/env python3
# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com


import unittest

from test_config import *

from lsassy.dumper import Dumper
from lsassy.impacketconnection import ImpacketConnection
from lsassy.impacketfile import ImpacketFile
from lsassy.log import Logger
from lsassy.defines import *


class Argument:
    def __init__(self,
                 target=None,
                 hashes=None,
                 method=None,
                 timeout=None,
                 dumpname=None,
                 procdump=None,
                 dumpert=None):
        self.target = target
        self.hashes = hashes
        self.method = method
        self.timeout = timeout
        self.dumpname = dumpname
        self.procdump = procdump
        self.dumpert = dumpert


class test_impacketconnection(unittest.TestCase):
    def setUp(self):
        self.log = Logger(is_debug=False, is_quiet=True)
        self.conn = None

    def tearDown(self):
        if isinstance(self.conn, ImpacketConnection):
            self.conn.close()

    def test_from_args_invalid_format(self):
        args = Argument("random")
        self.conn = ImpacketConnection.from_args(args, self.log)
        self.assertIsInstance(self.conn, RetCode)
        self.assertEqual(ERROR_INVALID_FORMAT[0], self.conn.error_code)
        self.tearDown()

        args = Argument("domain/user:pass")
        self.conn = ImpacketConnection.from_args(args, self.log)
        self.assertIsInstance(self.conn, RetCode)
        self.assertEqual(ERROR_INVALID_FORMAT[0], ImpacketConnection.from_args(args, self.log).error_code)
        self.tearDown()

        args = Argument("user:pass@domain.com:80")
        self.conn = ImpacketConnection.from_args(args, self.log)
        self.assertIsInstance(self.conn, RetCode)
        self.assertEqual(ERROR_INVALID_FORMAT[0], self.conn.error_code)
        self.tearDown()

    def test_login_dns_error(self):
        args = Argument("user:pass@unknown.pixisdomain")
        self.conn = ImpacketConnection.from_args(args, self.log)
        self.assertIsInstance(self.conn, RetCode)
        self.assertEqual(ERROR_DNS_ERROR[0], self.conn.error_code)
        self.tearDown()

    def test_login_connection_error(self):
        args = Argument("user:pass@255.255.255.255")
        self.conn = ImpacketConnection.from_args(args, self.log)
        self.assertIsInstance(self.conn, RetCode)
        self.assertEqual(ERROR_CONNEXION_ERROR[0], self.conn.error_code)
        self.tearDown()

    def test_login_login_error(self):
        args = Argument("user:pass@{}".format(ip_address))
        self.conn = ImpacketConnection.from_args(args, self.log)
        self.assertIsInstance(self.conn, RetCode)
        self.assertEqual(ERROR_LOGIN_FAILURE[0], self.conn.error_code)
        self.tearDown()

    def test_login_login_success(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address))
        self.conn = ImpacketConnection.from_args(args, self.log)
        self.assertIsInstance(self.conn, ImpacketConnection)
        self.tearDown()

    def test_is_admin(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address))
        self.conn = ImpacketConnection.from_args(args, self.log)
        res = self.conn.isadmin()
        self.assertEqual(ERROR_SUCCESS[0], res.error_code)
        self.tearDown()

    @unittest.skipUnless(usr_login and usr_password, "No low privileged user credential provided")
    def test_is_admin_error(self):
        args = Argument("{}/{}:{}@{}".format(domain, usr_login, usr_password, ip_address))
        self.conn = ImpacketConnection.from_args(args, self.log)
        res = self.conn.isadmin()
        self.assertEqual(ERROR_ACCESS_DENIED[0], res.error_code)
        self.tearDown()


class test_impacketfile(unittest.TestCase):
    def setUp(self):
        self.log = Logger(is_debug=False, is_quiet=True)
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address))
        self.conn = ImpacketConnection.from_args(args, self.log)
        self.ifile = ImpacketFile(self.conn, self.log)

    def tearDown(self):
        self.conn.close()

    def test_path_error(self):
        ret = self.ifile.open("RANDOM")
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_PATH_FILE[0], ret.error_code)

    def test_share_error(self):
        ret = self.ifile.open("RANDOM/path/file")
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_SHARE[0], ret.error_code)

    def test_file_error(self):
        ret = self.ifile.open("C$/path/file")
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_FILE[0], ret.error_code)

    def test_file_success(self):
        ret = self.ifile.open("C$/Windows/System32/calc.exe")
        self.assertIsInstance(ret, ImpacketFile)
        if isinstance(ret, ImpacketFile):
            ret.close()


class test_dumper(unittest.TestCase):
    def setUp(self):
        self.log = Logger(is_debug=False, is_quiet=True)
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address))
        self.conn = ImpacketConnection.from_args(args, self.log)

    def tearDown(self):
        self.conn.close()

    """
    DLL Method
    """

    def test_dll_dump_invalid_shell(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address))
        dump = Dumper(self.conn, args, self.log).dll_dump(("wmi",), "unknown")
        self.assertIsInstance(dump, RetCode)
        self.assertEqual(ERROR_UNDEFINED[0], dump.error_code)

    def test_dll_execute_error(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address))
        dump = Dumper(self.conn, args, self.log).dll_dump((), "cmd")
        self.assertIsInstance(dump, RetCode)
        self.assertEqual(ERROR_DLL_NO_EXECUTE[0], dump.error_code)

    def test_dll_execute_success(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address))
        dump = Dumper(self.conn, args, self.log).dll_dump(("task",), "cmd")
        self.assertIsInstance(dump, RetCode)
        self.assertEqual(ERROR_SUCCESS[0], dump.error_code)

    """
    Procdump Method
    """

    def test_procdump_missing_parameter(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address))
        dump = Dumper(self.conn, args, self.log).procdump_dump(("wmi",))
        self.assertIsInstance(dump, RetCode)
        self.assertEqual(ERROR_PROCDUMP_NOT_PROVIDED[0], dump.error_code)

    def test_procdump_invalid_parameter(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address), procdump="/random/file")
        dump = Dumper(self.conn, args, self.log).procdump_dump(())
        self.assertIsInstance(dump, RetCode)
        self.assertEqual(ERROR_PROCDUMP_NOT_FOUND[0], dump.error_code)

    @unittest.skipUnless(procdump_path, "Procdump path wasn't provided")
    def test_procdump_upload_error(self):
        args = Argument("{}/{}:{}@{}".format(domain, usr_login, usr_password, ip_address), procdump=procdump_path)
        dump = Dumper(self.conn, args, self.log)
        # Unknown share so procdump upload fails
        dump._share = "UNKNOWN_SHARE"
        dump = dump.procdump_dump(("task",))
        self.assertIsInstance(dump, RetCode)
        self.assertEqual(ERROR_PROCDUMP_NOT_UPLOADED[0], dump.error_code)

    @unittest.skipUnless(procdump_path, "Procdump path wasn't provided")
    def test_procdump_execute_error(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address), procdump=procdump_path)
        dump = Dumper(self.conn, args, self.log)
        ret = dump.procdump_dump(())
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_PROCDUMP_NO_EXECUTE[0], ret.error_code)
        dump.clean()

    """
    Dumpert Method
    """

    def test_dumpert_missing_parameter(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address))
        dump = Dumper(self.conn, args, self.log).dumpert_dump(("wmi",))
        self.assertIsInstance(dump, RetCode)
        self.assertEqual(ERROR_DUMPERT_NOT_PROVIDED[0], dump.error_code)

    def test_dumpert_invalid_parameter(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address), dumpert="/random/file")
        dump = Dumper(self.conn, args, self.log).dumpert_dump(())
        self.assertIsInstance(dump, RetCode)
        self.assertEqual(ERROR_DUMPERT_NOT_FOUND[0], dump.error_code)

    @unittest.skipUnless(dumpert_path, "Dumpert path wasn't provided")
    def test_dumpert_upload_error(self):
        args = Argument("{}/{}:{}@{}".format(domain, usr_login, usr_password, ip_address), dumpert=dumpert_path)
        dump = Dumper(self.conn, args, self.log)
        # Unknown share so dumpert upload fails
        dump._share = "UNKNOWN_SHARE"
        dump = dump.dumpert_dump(("task",))
        self.assertIsInstance(dump, RetCode)
        self.assertEqual(ERROR_DUMPERT_NOT_UPLOADED[0], dump.error_code)

    @unittest.skipUnless(dumpert_path, "Dumpert path wasn't provided")
    def test_dumpert_execute_error(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address), dumpert=dumpert_path)
        dump = Dumper(self.conn, args, self.log)
        ret = dump.dumpert_dump(())
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_DUMPERT_NO_EXECUTE[0], ret.error_code)
        dump.clean()

    """
    Dump generic
    """

    def test_dump_method_unknown(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address), method=99)
        dump = Dumper(self.conn, args, self.log).dump()
        self.assertIsInstance(dump, RetCode)
        self.assertEqual(ERROR_METHOD_NOT_SUPPORTED[0], dump.error_code)

    def test_dump_success(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address), method=4, timeout=5)
        dump = Dumper(self.conn, args, self.log).dump()
        self.assertIsInstance(dump, ImpacketFile)
        if isinstance(dump, ImpacketFile):
            dump.close()


class test_dumper_protected(unittest.TestCase):
    def setUp(self):
        self.log = Logger(is_debug=False, is_quiet=True)
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address_protected))
        self.conn = ImpacketConnection.from_args(args, self.log)

    def tearDown(self):
        self.conn.close()

    @unittest.skipUnless(procdump_path, "Procdump path wasn't provided")
    @unittest.skipUnless(ip_address_protected, "No IP address with protected LSASS was provided")
    def test_dump_protected(self):
        args = Argument("{}/{}:{}@{}".format(domain, da_login, da_password, ip_address_protected), method=2,
                        procdump=procdump_path, timeout=5)
        dump = Dumper(self.conn, args, self.log).dump()
        self.assertIsInstance(dump, RetCode)
        self.assertEqual(ERROR_LSASS_PROTECTED[0], dump.error_code)


unittest.main()
