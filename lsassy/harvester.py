import importlib
import logging

from lsassy.dpapi.config.module_management import get_modules
from lsassy.credential import Credential
from lsassy.dpapi.recon import Recon
from lsassy.dpapi.module.firefox import Mozilla, firefox_browsers


class Harvester:
    def __init__(self, session):
        self.session = session
        self.users = []

    def harvest(self, categories=None):
        self.users = Recon(self.session).enumerate_users()
        modules = [module for module in get_modules() if categories is None or module.category in categories]

        credentials = []

        for user in self.users:
            for module in modules:
                module.setup(self.session, user)
                cred = module.run()
                for c in cred:
                    c.set_source(module.name.upper())
                    credentials.append(c)
        return credentials

