from lsassy.impacketfile import ImpacketFile


class Recon:
    def __init__(self, session):
        self._session = session
        self._file_handle = None

    def enumerate_users(self):
        users = []
        for f in self._session.smb_session.listPath("C$", "Users\\*"):
            if f.is_directory() > 0 and f.get_longname() not in [".", ".."]:
                users.append(f.get_longname())
        return users
