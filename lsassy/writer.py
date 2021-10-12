import logging
from pathlib import Path
import os

import importlib


class Writer:
    """
    Class used to write output results either on screen and/or in a file
    """
    def __init__(self, credentials, tickets):
        self._credentials = credentials
        self._tickets = tickets

    def get_output(self, out_format, users_only=False):
        """
        Get credentials output in given format
        :param out_format: Format from output package
        :param users_only: If set, only returns users account, else returns users and computers accounts
        :return: Output string
        """
        try:
            output_method = importlib.import_module("lsassy.output.{}_output".format(out_format.lower()), "Output").Output(self._credentials, users_only)
        except ModuleNotFoundError:
            logging.error("Output module '{}' doesn't exist".format(out_format.lower()), exc_info=True)
            return None

        return output_method.get_output()

    def write(self, out_format="pretty", output_file=None, quiet=False, users_only=False, kerberos_dir=None):
        """
        Displays content to stdout and/or a file
        :param out_format: Output format
        :param output_file: Output file
        :param quiet: If set, doesn't display on stdout
        :param users_only: If set, only returns users account, else returns users and computers accounts
        :return: Success status
        """
        output = self.get_output(out_format, users_only)
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

        if kerberos_dir is not None:
            if len(self._tickets) == 0 and not quiet:
                logging.warning("No kerberos tickets found")
                return True
            abs_dir = os.path.abspath(kerberos_dir)
            if not os.path.exists(abs_dir):
                try:
                    os.makedirs(abs_dir)
                except Exception as e:
                    logging.warning("Cannot create %s for saving kerberos tickets" % abs_dir, exc_info=True)
                    return True
            for ticket in self._tickets:
                ticket.to_kirbi(abs_dir)
            if not quiet:
                if len(self._tickets) > 1:
                    logging.success("%s Kerberos tickets written to %s" % (len(self._tickets),abs_dir))
                else:
                    logging.success("%s Kerberos ticket written to %s" % (len(self._tickets),abs_dir))
        return True
