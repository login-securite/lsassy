from lsassy.impacketfile import ImpacketFile


class ModuleInfo(object):

    def __init__(self, name, category, suboptions=None, registry_used=False, winapi_used=False,
                 system_module=False, dpapi_used=False, only_from_current_user=False):
        self.name = name
        self.category = category
        self.options = {
            'command': '-{name}'.format(name=self.name),
            'action': 'store_true',
            'dest': self.name,
            'help': '{name} passwords'.format(name=self.name)
        }
        self.suboptions = suboptions if suboptions is not None else []
        self.registry_used = registry_used
        self.system_module = system_module
        self.winapi_used = winapi_used
        self.dpapi_used = dpapi_used
        self.only_from_current_user = only_from_current_user
        self.session = None
        self.impacketfile = None
        self.user = None

    def setup(self, session, user):
        self.session = session
        self.impacketfile = ImpacketFile(session)
        self.user = user
