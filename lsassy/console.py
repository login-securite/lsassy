import argparse
import sys

from lsassy import __version__
from lsassy.core import ThreadPool
from lsassy.dumper import Dumper


def main():
    """
        Command line function to call lsassy
        """
    version = __version__
    parser = argparse.ArgumentParser(
        prog="lsassy",
        description='lsassy v{} - Remote lsass dump reader'.format(__version__)
    )

    group_dump = parser.add_argument_group('dump')
    group_dump.add_argument('-m', '--dump-method', action='store', default="comsvcs",
                            help="Dumping method ({})".format(', '.join(Dumper.list_dump_methods())))
    group_dump.add_argument('--dump-path', action='store',
                            help='Path to store lsass dumpfile (Default: \\Windows\\Temp)')
    group_dump.add_argument('--dump-name', action='store', help='Name given to lsass dumpfile (Default: Random)')
    group_dump.add_argument('-e', '--exec', action='store',
                            help='List of execution methods, comma separated (From {})'.format(', '.join(Dumper.list_exec_methods())))
    group_dump.add_argument('--no-powershell', action='store_true', help='Disable PowerShell')
    group_dump.add_argument('--copy', action='store_true', help='Copies cmd or powershell with random name before using it')
    group_dump.add_argument('-O', '--options', action='store',
                            help='Dump module options (Example procdump_path=/opt/procdump.exe,procdump=procdump.exe')
    group_dump.add_argument('--timeout', action='store', type=int, default=5,
                            help='Max time to wait for lsass dump (Default 5s)')
    group_dump.add_argument('--time-between-commands', action='store', type=int, default=7,
                            help='Time to wait between dump methods commands (Default 7s)')
    group_dump.add_argument('--parse-only', action='store_true', help='Parse dump without dumping')
    group_dump.add_argument('--keep-dump', action='store_true', help='Parse dump without dumping')

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
    group_auth.add_argument('-aesKey', action="store", metavar="hex key",
                            help='AES key to use for Kerberos Authentication '
                                 '(128 or 256 bits)')

    group_out = parser.add_argument_group('output')
    group_out.add_argument('-K', '--kerberos-dir', action='store', help='Save kerberos tickets to a directory')
    group_out.add_argument('-M', '--masterkeys-file', action='store', help='Save masterkeys in format {GUID}:SHA1 to a file')
    group_out.add_argument('-o', '--outfile', action='store', help='Output credentials to file')
    group_out.add_argument('-f', '--format', choices=["pretty", "json", "grep", "table"], action='store', default="pretty",
                           help='Output format (Default pretty)')
    group_out.add_argument('-ff', '--file-format', choices=["pretty", "json", "grep", "table"], action='store',
                           help='File format (Default same value as --format)')
    group_out.add_argument('-nc', '--no-color', action='store_true', help='No colors in output')
    

    group_out.add_argument('--users', action='store_true', help='Only display user accounts (No computer accounts)')
    group_out.add_argument('--no-tickets', action='store_true', help='Do not display valid TGT')
    group_out.add_argument('--masterkeys', action='store_true', help='Display valid masterkeys')

    parser.add_argument('-v', action='count', default=0, help='Verbosity level (-v or -vv)')
    parser.add_argument('--threads', default=10, type=int, action='store', help='Threads number')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode, only display credentials')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s (version {})'.format(version))
    parser.add_argument('target', nargs='*', type=str, action='store',
                        help='The target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) '
                             'containing a list of targets')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    ThreadPool(args.target, args).run()


if __name__ == "__main__":
    main()
