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
ERROR_PATH_FILE             = (9, "Invalid path")
ERROR_SHARE                 = (10, "Error opening share")
ERROR_FILE                  = (11, "Error opening file")
ERROR_INVALID_FORMAT        = (12, "Invalid format")
ERROR_DNS_ERROR             = (13, "No DNS found to resolve this hostname")
ERROR_LOGIN_FAILURE         = (14, "Authentication error")
ERROR_PROCDUMP_NOT_FOUND    = (15, "Procdump path is not valid")
ERROR_PROCDUMP_NOT_PROVIDED = (16, "Procdump was not provided")
ERROR_PROCDUMP_NOT_UPLOADED = (17, "Procdump could not be uploaded")
ERROR_DLL_NO_EXECUTE        = (18, "Could not execute commands on remote host via DLL")
ERROR_PROCDUMP_NO_EXECUTE   = (19, "Could not execute commands on remote host via WMI")
ERROR_DUMPERT_NO_EXECUTE    = (20, "Could not execute commands on remote host via WMI")
ERROR_DUMPERT_NOT_FOUND     = (21, "dumpert path is not valid")
ERROR_DUMPERT_NOT_PROVIDED  = (22, "dumpert was not provided")
ERROR_DUMPERT_NOT_UPLOADED  = (23, "dumpert could not be uploaded")

ERROR_UNDEFINED             = (99, "Unknown error")


class RetCode:
    def __init__(self, error, exception=None):
        self.error_code = error[0]
        self.error_msg = error[1]
        self.error_exception = exception

    def success(self):
        return self.error_code == 0

    def __str__(self):
        return "{} : {}".format(self.error_code, self.error_msg)
