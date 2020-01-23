# lsassy

[![PyPI version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=py&type=6&v=2.0.1&x2=0)](https://pypi.org/project/lsassy/) [![Twitter](https://img.shields.io/twitter/follow/hackanddo?label=HackAndDo&style=social)](https://twitter.com/intent/follow?screen_name=hackanddo)

![CME Module example](https://github.com/Hackndo/lsassy/raw/master/assets/example.png)

Python library to remotely extract credentials on a set of hosts. This [blog post](https://en.hackndo.com/remote-lsass-dump-passwords/) explains how it works.

This library uses [impacket](https://github.com/SecureAuthCorp/impacket) project to remotely read necessary bytes in lsass dump and [pypykatz](https://github.com/skelsec/pypykatz) to extract credentials.

| Chapters                                     | Description                                             |
|----------------------------------------------|---------------------------------------------------------|
| [Requirements](#requirements)                | Requirements to install lsassy from source              |
| [Installation](#installation)                | Installation commands from pip or from source           |
| [Documentation](#documentation)              | Lsassy documentation                                    |
| [CrackMapExec Module](#crackmapexec-module)  | Link to CrackMapExec module included in this repository |
| [Issues](#issues)                            | Read this before creating an issue                      |
| [Acknowledgments](#acknowledgments)          | Kudos to these people and tools                         |
| [Contributors](#contributors)                | People contributing to this tool                        |

## Requirements

* Python >= 3.6
* netaddr
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

## Documentation

The tool is fully documented in the [wiki](https://github.com/Hackndo/lsassy/wiki) of this project

## CrackMapExec module

I wrote a CrackMapExec module that uses **lsassy** to extract credentials on compromised hosts

CrackMapExec module is in `cme` folder : [CME Module](https://github.com/Hackndo/lsassy/tree/master/cme)


### ChangeLog

```
v2.0.0
------
* Multiprocessing support to dump credentials on multiple hosts at a time
* Add new dumping method using "dumpert"
* Can be used as a library in other python projects
* Syntax changed to be more flexible
* Complete code refactoring, way more organized and easy to maintain/extend
* Better error handling
* Complete wiki

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
* [blurbdust](https://github.com/blurbdust)
