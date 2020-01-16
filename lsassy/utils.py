# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import sys


def lsassy_exit(logger, error):
    if error.error_msg:
        logger.error(error.error_msg)
    if error.error_exception:
        logger.debug("Error : {}".format(error.error_exception))
    sys.exit(error.error_code)
