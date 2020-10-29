from lsassy.dpapi.config.moduleinfo import ModuleInfo

from lsassy.dpapi.module.firefox import Mozilla


class Thunderbird(Mozilla):

    def __init__(self):
        self.path = u'{APPDATA}\\Thunderbird'
        ModuleInfo.__init__(self, 'Thunderbird', category='mails')
