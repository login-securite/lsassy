import logging
from pathlib import Path
import os

import importlib


class Writer:
    def __init__(self, credentials):
        self._credentials = credentials

    def get_output(self, out_format):

        try:
            output_method = importlib.import_module("lsassy.output.{}_output".format(out_format.lower()), "Output").Output(self._credentials)
        except ModuleNotFoundError:
            logging.error("Output module '{}' doesn't exist".format(out_format.lower()), exc_info=True)
            return None

        return output_method.get_output()

    def write(self, out_format="pretty", output_file=None, quiet=False):
        output = self.get_output(out_format)
        if output is None:
            logging.error("An error occurred while writing credentials", exc_info=True)
            return None

        if not quiet:
            print(output, end="\n")

        if output_file is not None:
            path = Path(output_file).parent
            if not os.path.isdir(path):
                logging.error("Directory {} does not exist".format(path))
                return None

            with open(output_file, 'a+') as f:
                f.write(output + "\n")
            logging.success("Credentials saved to {}".format(output_file))
        return True
