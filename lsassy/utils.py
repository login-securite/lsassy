# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import sys
import os
import pkg_resources
from netaddr import IPAddress, IPRange, IPNetwork, AddrFormatError
from lsassy.defines import *

version = pkg_resources.require("lsassy")[0].version


def get_args():
    import argparse

    examples = '''examples:
    
    ** RunDLL Dump Method **
    lsassy adsec.local/pixis:p4ssw0rd@dc01.adsec.local
    
    ** Try all methods **
    lsassy -m 0 adsec.local/pixis:p4ssw0rd@dc01.adsec.local
    
    ** Procdump Dump Method **
    lsassy -m 2 -p /tmp/procdump.exe adsec.local/pixis:p4ssw0rd@dc01.adsec.local
    
    ** dumpert Dump Method **
    lsassy -m 5 -u /tmp/dumpert.exe adsec.local/pixis:p4ssw0rd@dc01.adsec.local
    
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
    0: Try all methods (dll then procdump then dumpert) to dump lsass, stop on success (Requires -p if dll method fails, -u if procdump method fails)
    1: comsvcs.dll method, stop on success (default)
    2: Procdump method, stop on success (Requires -p)
    3: comsvcs.dll + Powershell method, stop on success
    4: comsvcs.dll + cmd.exe method
    5: (unsafe) dumpert method, stop on success (Requires -u)''')
    group_dump.add_argument('--dumpname', action='store', help='Name given to lsass dump (Default: Random)')
    group_dump.add_argument('--procdump', action='store', help='Procdump path')
    group_dump.add_argument('--dumpert', action='store', help='dumpert path')
    group_dump.add_argument('--timeout', default="10", action='store',
                            help='Timeout before considering lsass was not dumped successfully')

    group_auth = parser.add_argument_group('authentication')
    group_auth.add_argument('-u', '--username', action='store', help='Username')
    group_auth.add_argument('-p', '--password', action='store', help='Plaintext password')
    group_auth.add_argument('-d', '--domain', default="", action='store', help='Domain name')
    group_auth.add_argument('-H', '--hashes', action='store', help='[LM:]NT hash')

    group_out = parser.add_argument_group('output')
    group_out.add_argument('-j', '--json', action='store_true', help='Print credentials in JSON format')
    group_out.add_argument('-g', '--grep', action='store_true', help='Print credentials in greppable format')
    group_extract = parser.add_argument_group('remote parsing only')
    group_extract.add_argument('--dumppath', action='store', help='lsass dump path (Format : c$/Temp/lsass.dmp)')

    parser.add_argument('-r', '--raw', action='store_true',
                        help='No basic result filtering (Display host credentials and duplicates)')
    parser.add_argument('--debug', action='store_true', help='Debug output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode, only display credentials')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s (version {})'.format(version))
    parser.add_argument('target', nargs='*', type=str, action='store', help='The target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(RetCode(ERROR_MISSING_ARGUMENTS).error_code)

    return parser.parse_args()


def lsassy_exit(logger, error):
    if error.error_msg:
        logger.error(error.error_msg)
    if error.error_exception:
        logger.debug("Error : {}".format(error.error_exception))
    sys.exit(error.error_code)


def lsassy_warn(logger, error):
    if error.error_msg:
        logger.warn(error.error_msg)
    if error.error_exception:
        logger.debug("Error : {}".format(error.error_exception))


def is_valid_ip(ip):
    ip = ip.split(".")
    if len(ip) != 4:
        return False
    return all([0 <= int(t) <= 255 for t in ip])


def get_log_max_spaces(targets):
    return max(len(t) for t in targets) + 4


def get_log_spaces(target, spaces):
    return spaces - len(target)


def parse_targets(target):
    if '-' in target:
        ip_range = target.split('-')
        try:
            t = IPRange(ip_range[0], ip_range[1])
        except AddrFormatError:
            try:
                start_ip = IPAddress(ip_range[0])

                start_ip_words = list(start_ip.words)
                start_ip_words[-1] = ip_range[1]
                start_ip_words = [str(v) for v in start_ip_words]

                end_ip = IPAddress('.'.join(start_ip_words))

                t = IPRange(start_ip, end_ip)
            except AddrFormatError:
                t = target
    else:
        try:
            t = IPNetwork(target)
        except AddrFormatError:
            t = target
    if type(t) == IPNetwork or type(t) == IPRange:
        return list(t)
    else:
        return [t.strip()]


def get_targets(targets):
    ret_targets = []
    for target in targets:
        if os.path.exists(target):
            with open(target, 'r') as target_file:
                for target_entry in target_file:
                    ret_targets += parse_targets(target_entry)
        else:
            ret_targets += parse_targets(target)
    return [str(ip) for ip in ret_targets]
