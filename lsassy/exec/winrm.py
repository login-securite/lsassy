from lsassy.exec import IExec



class Exec(IExec):
    """
    Remote execution using service creation as SYSTEM

    This execution method provides debug privilege
    """

    debug_privilege = False

    def clean(self):
        # no cleanup needed after code execution
        pass

    def exec(self, command):
        # "success" is not really success but if it has ever encountered a problem during powershell execution.
        # this can also happen if everything works like in an ls but it encounters one file it cant read
        # maybe parsing the stderr from the result_object would yield better results
        result, result_object, success = self.session.smb_session.execute_ps(command)
        #TODO: better determine success
        return True
