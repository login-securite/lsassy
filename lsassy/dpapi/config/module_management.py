from lsassy.dpapi.module.pidgin import Pidgin

from lsassy.dpapi.module.postgresql import PostgreSQL
from lsassy.dpapi.module.thunderbird import Thunderbird
from lsassy.dpapi.module.firefox import firefox_browsers


def get_categories():
    category = {
        'browsers': {'help': 'Web browsers supported'},
        'chats': {'help': 'Chat clients supported'},
        'databases': {'help': 'SQL/NoSQL clients supported'},
        'games': {'help': 'Games etc.'},
        'git': {'help': 'GIT clients supported'},
        'mails': {'help': 'Email clients supported'},
        'maven': {'help': 'Maven java build tool'},
        'memory': {'help': 'Retrieve passwords from memory'},
        'multimedia': {'help': 'Multimedia applications, etc'},
        'php': {'help': 'PHP build tool'},
        'svn': {'help': 'SVN clients supported'},
        'sysadmin': {'help': 'SCP/SSH/FTP/FTPS clients supported'},
        'windows': {'help': 'Windows credentials (credential manager, etc.)'},
        'wifi': {'help': 'Wifi'},
    }
    return category


def get_modules():
    module_names = [
        Thunderbird(),
        PostgreSQL(),
        Pidgin()
    ]
    return module_names + firefox_browsers
