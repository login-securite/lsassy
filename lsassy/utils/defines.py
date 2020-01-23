# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

ERROR_SUCCESS               = (0, "")
ERROR_NO_CREDENTIAL_FOUND   = (0, "Procdump could not be uploaded")

ERROR_MISSING_ARGUMENTS     = (1, "")
ERROR_CONNECTION_ERROR      = (2, "Connection error")
ERROR_ACCESS_DENIED         = (3, "Access denied. Administrative rights on remote host are required")
ERROR_METHOD_NOT_SUPPORTED  = (4, "Method not supported")
ERROR_LSASS_PROTECTED       = (5, "Lsass is protected")
ERROR_SLOW_TARGET           = (6, "Either lsass is protected or target might be slow. Try to increase --timeout")
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
ERROR_DLL_NO_EXECUTE        = (18, "Could not execute commands on remote host via DLL method")
ERROR_PROCDUMP_NO_EXECUTE   = (19, "Could not execute commands on remote host via Procdump method")
ERROR_DUMPERT_NO_EXECUTE    = (20, "Could not execute commands on remote host via Dumpert method")
ERROR_DUMPERT_NOT_FOUND     = (21, "dumpert path is not valid")
ERROR_DUMPERT_NOT_PROVIDED  = (22, "dumpert was not provided")
ERROR_DUMPERT_NOT_UPLOADED  = (23, "dumpert could not be uploaded")
ERROR_OUTPUT_FORMAT_INVALID = (24, "Output format is not valid")
ERROR_OUTPUT_DIR_NOT_EXIST  = (25, "Output directory does not exist")

# Cleaning errors
ERROR_DUMP_CLEANING         = (100, "Error while cleaning lsass dump")
ERROR_PROCDUMP_CLEANING     = (101, "Error while cleaning procdump")
ERROR_DUMPERT_CLEANING      = (102, "Error while cleaning dumpert")
ERROR_CONNECTION_CLEANING   = (103, "Error while cleaning connection")

ERROR_UNDEFINED             = (-1, "Unknown error")


class RetCode:
    def __init__(self, error, exception=None):
        self.error_code = error[0]
        self.error_msg = error[1]
        self.error_exception = exception

    def success(self):
        return self.error_code == 0

    def __str__(self):
        return "{} : {}".format(self.error_code, self.error_msg)

    def __eq__(self, other):
        if isinstance(other, RetCode):
            return self.error_code == other.error_code
        elif isinstance(other, int):
            return self.error_code == other
        return NotImplemented

    def __ne__(self, other):
        x = self.__eq__(other)
        if x is not NotImplemented:
            return not x
        return NotImplemented

    def __hash__(self):
        return hash(tuple(sorted(self.__dict__.items())))
