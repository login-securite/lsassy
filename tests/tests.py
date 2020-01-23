#!/usr/bin/env python3
# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com


import unittest

from lsassy.utils.defines import *
from lsassy.modules.dumper import Dumper
from lsassy.modules.impacketconnection import ImpacketConnection
from lsassy.modules.impacketfile import ImpacketFile
from lsassy.modules.logger import Logger
from lsassy.modules.writer import Writer
from lsassy.core import Lsassy
from tests.tests_config import *


class test_impacketconnection(unittest.TestCase):
    def setUp(self):
        self.log = Logger(Logger.Options(verbosity=0, quiet=True))
        self.conn = None

    def tearDown(self):
        if isinstance(self.conn, ImpacketConnection):
            self.conn.clean()

    def test_login_dns_error(self):
        self.conn = ImpacketConnection(ImpacketConnection.Options("pixis.hackndo", domain, da_login, da_password))
        self.conn.set_logger(self.log)
        ret = self.conn.login()
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_DNS_ERROR[1], ret.error_msg)

    def test_login_connection_error(self):
        self.conn = ImpacketConnection(ImpacketConnection.Options("255.255.255.255", domain, da_login, da_password))
        self.conn.set_logger(self.log)
        ret = self.conn.login()
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_CONNECTION_ERROR[1], ret.error_msg)

    def test_login_login_error(self):
        self.conn = ImpacketConnection(ImpacketConnection.Options(ip_address, domain, da_login, "wrong_password"))
        self.conn.set_logger(self.log)
        ret = self.conn.login()
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_LOGIN_FAILURE[1], ret.error_msg)

    def test_login_login_success(self):
        self.conn = ImpacketConnection(ImpacketConnection.Options(ip_address, domain, da_login, da_password))
        self.conn.set_logger(self.log)
        ret = self.conn.login()
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_SUCCESS[1], ret.error_msg)

    def test_is_admin(self):
        self.conn = ImpacketConnection(ImpacketConnection.Options(ip_address, domain, da_login, da_password))
        self.conn.set_logger(self.log)
        self.conn.login()
        ret = self.conn.isadmin()
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_SUCCESS[1], ret.error_msg)

    @unittest.skipUnless(usr_login and usr_password, "No low privileged user credential provided")
    def test_is_admin_error(self):
        self.conn = ImpacketConnection(ImpacketConnection.Options(ip_address, domain, usr_login, usr_password))
        self.conn.set_logger(self.log)
        self.conn.login()
        ret = self.conn.isadmin()
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_ACCESS_DENIED[1], ret.error_msg)


class test_impacketfile(unittest.TestCase):
    def setUp(self):
        self.log = Logger(Logger.Options(verbosity=0, quiet=True))
        self.conn = ImpacketConnection(ImpacketConnection.Options(ip_address, domain, da_login, da_password))
        self.conn.set_logger(self.log)
        self.conn.login()
        self.ifile = ImpacketFile(self.conn, self.log)

    def tearDown(self):
        self.ifile.clean()
        self.conn.clean()

    def test_path_error(self):
        ret = self.ifile.open("RANDOM")
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_PATH_FILE[1], ret.error_msg)

    def test_share_error(self):
        ret = self.ifile.open("RANDOM/path/file")
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_SHARE[1], ret.error_msg)

    def test_file_error(self):
        ret = self.ifile.open("C$/path/file")
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_FILE[1], ret.error_msg)

    def test_file_success(self):
        ret = self.ifile.open("C$/Windows/System32/calc.exe")
        ret.clean()
        self.assertIsInstance(ret, ImpacketFile)


class test_dumper(unittest.TestCase):
    def setUp(self):
        self.log = Logger(Logger.Options(verbosity=0, quiet=True))
        self.conn = ImpacketConnection(ImpacketConnection.Options(ip_address, domain, da_login, da_password))
        self.conn.set_logger(self.log)
        self.conn.login()

    def tearDown(self):
        self.conn.clean()

    """
    DLL Method
    """
    def test_dll_dump_invalid_shell(self):
        ret = Dumper(self.conn).dll_dump(("wmi",), "unknown")
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_METHOD_NOT_SUPPORTED[1], ret.error_msg)

    def test_dll_execute_error(self):
        ret = Dumper(self.conn).dll_dump((), "cmd")
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_DLL_NO_EXECUTE[1], ret.error_msg)

    def test_dll_execute_success(self):
        ret = Dumper(self.conn).dll_dump(("task",), "cmd")
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_SUCCESS[1], ret.error_msg)

    """
    Procdump Method
    """
    def test_procdump_missing_parameter(self):
        ret = Dumper(self.conn).procdump_dump(("wmi",))
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_PROCDUMP_NOT_PROVIDED[1], ret.error_msg)

    def test_procdump_invalid_parameter(self):
        dump_option = Dumper.Options()
        dump_option.procdump_path = "/invalid/path"
        ret = Dumper(self.conn, dump_option).procdump_dump(())
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_PROCDUMP_NOT_FOUND[1], ret.error_msg)

    @unittest.skipUnless(procdump_path, "Procdump path wasn't provided")
    def test_procdump_upload_error(self):
        dump_option = Dumper.Options()
        dump_option.procdump_path = procdump_path
        dump_option.share = "INVALID_SHARE"
        ret = Dumper(self.conn, dump_option).procdump_dump(())
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_PROCDUMP_NOT_UPLOADED[1], ret.error_msg)

    @unittest.skipUnless(procdump_path, "Procdump path wasn't provided")
    def test_procdump_execute_error(self):
        dump_option = Dumper.Options()
        dump_option.procdump_path = procdump_path
        dump = Dumper(self.conn, dump_option)
        ret = dump.procdump_dump(())
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_PROCDUMP_NO_EXECUTE[1], ret.error_msg)
        dump.clean()

    """
    Dumpert Method
    """
    def test_dumpert_missing_parameter(self):
        ret = Dumper(self.conn).dumpert_dump(("wmi",))
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_DUMPERT_NOT_PROVIDED[1], ret.error_msg)

    def test_dumpert_invalid_parameter(self):
        dump_option = Dumper.Options()
        dump_option.dumpert_path = "/invalid/path"
        ret = Dumper(self.conn, dump_option).dumpert_dump(())
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_DUMPERT_NOT_FOUND[1], ret.error_msg)

    @unittest.skipUnless(dumpert_path, "Dumper path wasn't provided")
    def test_dumpert_upload_error(self):
        dump_option = Dumper.Options()
        dump_option.dumpert_path = dumpert_path
        dump_option.share = "INVALID_SHARE"
        ret = Dumper(self.conn, dump_option).dumpert_dump(())
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_DUMPERT_NOT_UPLOADED[1], ret.error_msg)

    @unittest.skipUnless(dumpert_path, "Dumper path wasn't provided")
    def test_dumpert_execute_error(self):
        dump_option = Dumper.Options()
        dump_option.dumpert_path = dumpert_path
        dumper = Dumper(self.conn, dump_option)
        ret = dumper.dumpert_dump(())
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_DUMPERT_NO_EXECUTE[1], ret.error_msg)
        dumper.clean()

    """
    Dump generic
    """
    def test_dump_method_unknown(self):
        dump_option = Dumper.Options()
        dump_option.method = 99
        ret = Dumper(self.conn, dump_option).dump()
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_METHOD_NOT_SUPPORTED[1], ret.error_msg)

    def test_dump_success(self):
        dumper = Dumper(self.conn)
        ret = dumper.dump()
        dumper.clean()
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_SUCCESS[1], ret.error_msg)




@unittest.skipUnless(procdump_path, "Procdump path wasn't provided")
@unittest.skipUnless(ip_address_protected, "No IP address with protected LSASS was provided")
class test_dumper_protected(unittest.TestCase):
    def setUp(self):
        self.log = Logger(Logger.Options(verbosity=0, quiet=True))
        self.conn = ImpacketConnection(ImpacketConnection.Options(ip_address_protected, domain, da_login, da_password))
        self.conn.set_logger(self.log)
        self.conn.login()

    def tearDown(self):
        self.conn.clean()

    def test_dump_protected(self):
        dump_option = Dumper.Options()
        dump_option.method = 2
        dump_option.procdump_path = procdump_path
        dumper = Dumper(self.conn, dump_option)
        ret = dumper.dump()
        self.assertIsInstance(ret, RetCode)
        self.assertEqual(ERROR_LSASS_PROTECTED[1], ret.error_msg)
        dumper.clean()

class test_lsassy(unittest.TestCase):
    def setUp(self):
        log_options = Logger.Options(verbosity=0, quiet=True)
        write_options = Writer.Options(format="none")
        self.lsassy = Lsassy(ip_address, da_login, domain, da_password, log_options=log_options, write_options=write_options)

    def tearDown(self):
        self.lsassy.clean()

    def test_lsassy_success(self):
        ret = self.lsassy.run()
        self.assertEqual(0, ret)


if __name__ == '__main__':
    unittest.main()

