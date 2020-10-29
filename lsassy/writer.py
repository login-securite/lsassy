import logging
from pathlib import Path
import os

import importlib


class Writer:
    """
    Class used to write output results either on screen and/or in a file
    """
    def __init__(self, credentials):
        self._credentials = credentials

    def get_output(self, out_format, users_only=False, dpapi=False):
        """
        Get credentials output in given format
        :param out_format: Format from output package
        :param users_only: If set, only returns users account, else returns users and computers accounts
        :param dpapi: If set, set output to DPAPI credentials format
        :return: Output string
        """
        try:
            output_method = importlib.import_module("lsassy.output.{}_output".format(out_format.lower()), "Output").Output(self._credentials, users_only)
        except ModuleNotFoundError:
            logging.error("Output module '{}' doesn't exist".format(out_format.lower()), exc_info=True)
            return None

        return output_method.get_output()

    def write(self, out_format="pretty", output_file=None, quiet=False, users_only=False, dpapi=False):
        """
        Displays content to stdout and/or a file
        :param out_format: Output format
        :param output_file: Output file
        :param quiet: If set, doesn't display on stdout
        :param users_only: If set, only returns users account, else returns users and computers accounts
        :param dpapi: If set, set output to DPAPI credentials format
        :return: Success status
        """
        output = self.get_output(out_format, users_only=users_only, dpapi=dpapi)
        if output is None:
            logging.error("An error occurred while writing credentials", exc_info=True)
            return None

        if not quiet:
            for line in output.split("\n"):
                logging.success(line)

        if output_file is not None:
            path = Path(output_file).parent
            if not os.path.isdir(path):
                logging.error("Directory {} does not exist".format(path))
                return None

            with open(output_file, 'a+') as f:
                f.write(output + "\n")
            logging.success("Credentials saved to {}".format(output_file))
        return True
