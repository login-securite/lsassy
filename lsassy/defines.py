# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

ERROR_SUCCESS               = (0, "")
ERROR_NO_CREDENTIAL_FOUND   = (0, "Procdump could not be uploaded")

ERROR_MISSING_ARGUMENTS     = (1, "")
ERROR_CONNEXION_ERROR       = (2, "Connexion error")
ERROR_ACCESS_DENIED         = (3, "Access denied. Administrative rights on remote host are required")
ERROR_METHOD_NOT_SUPPORTED  = (4, "Method not supported")
ERROR_LSASS_PROTECTED       = (5, "Lsass is protected")
ERROR_SLOW_TARGET           = (6, "Target might be slow. Try to increase --timeout")
ERROR_LSASS_DUMP_NOT_FOUND  = (7, "lsass dump file does not exist. Use --debug flag for more details")
ERROR_USER_INTERRUPTION     = (8, "lsassy has been interrupted")
ERROR_SHARE                 = (9, "Error opening share")
ERROR_FILE                  = (10, "Error opening file")
ERROR_INVALID_FORMAT        = (11, "Invalid format")
ERROR_DNS_ERROR             = (12, "No DNS found to resolve this hostname")
ERROR_LOGIN_FAILURE         = (13, "Authentication error")
ERROR_PROCDUMP_NOT_FOUND    = (14, "Procdump path is not valid")
ERROR_PROCDUMP_NOT_PROVIDED = (15, "Procdump was not provided")
ERROR_PROCDUMP_NOT_UPLOADED = (16, "Procdump could not be uploaded")
ERROR_DLL_NO_EXECUTE        = (17, "Counln't execute commands on remote host via DLL")
ERROR_WMI_NO_EXECUTE        = (18, "Counln't execute commands on remote host via WMI")
ERROR_UNDEFINED             = (99, "Unknown error")


class RetCode:
    def __init__(self, error, exception=None):
        self.error_code = error[0]
        self.error_msg = error[1]
        self.error_exception = exception

    def success(self):
        return self.error_code == 0
