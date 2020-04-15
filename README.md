# lsassy

[![PyPI version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=py&type=6&v=2.1.2&x2=0)](https://pypi.org/project/lsassy/) [![Twitter](https://img.shields.io/twitter/follow/hackanddo?label=HackAndDo&style=social)](https://twitter.com/intent/follow?screen_name=hackanddo)

![Example](https://github.com/Hackndo/lsassy/raw/master/assets/example.png)

Python library to remotely extract credentials on a set of hosts. This [blog post](https://en.hackndo.com/remote-lsass-dump-passwords/) explains how it works.

This library uses [impacket](https://github.com/SecureAuthCorp/impacket) project to remotely read necessary bytes in lsass dump and [pypykatz](https://github.com/skelsec/pypykatz) to extract credentials.

| Chapters                                     | Description                                             |
|----------------------------------------------|---------------------------------------------------------|
| [Requirements](#requirements)                | Requirements to install lsassy from source              |
| [Documentation](#documentation)              | Lsassy documentation                                    |
| [CrackMapExec Module](#crackmapexec-module)  | Link to CrackMapExec module included in this repository |
| [Issues](#issues)                            | Read this before creating an issue                      |
| [Acknowledgments](#acknowledgments)          | Kudos to these people and tools                         |
| [Contributors](#contributors)                | People contributing to this tool                        |

## Requirement

* Python >= 3.6

## Documentation

The tool is fully documented in the project's [wiki](https://github.com/Hackndo/lsassy/wiki)

### Installation

* [Installation](https://github.com/Hackndo/lsassy/wiki/Lsassy-Installation)

### Standalone

* [Basic Usage](https://github.com/Hackndo/lsassy/wiki/Lsassy-Basic-Usage)
* [Advanced Usage](https://github.com/Hackndo/lsassy/wiki/Lsassy-Advanced-Usage)

### Library

* [Basic Usage](https://github.com/Hackndo/lsassy/wiki/Lsassy-lib-Basic-Usage)
* [Advanced Usage](https://github.com/Hackndo/lsassy/wiki/Lsassy-lib-Advanced-Usage)

### CrackMapExec module

* [Installation](https://github.com/Hackndo/lsassy/wiki/CME-Installation)
* [Basic Usage](https://github.com/Hackndo/lsassy/wiki/CME-Basic-Usage)
* [Advanced Usage](https://github.com/Hackndo/lsassy/wiki/CME-Advanced-Usage)

## CrackMapExec module

I wrote a CrackMapExec module that uses **lsassy** to extract credentials on compromised hosts

CrackMapExec module is in `cme` folder : [CME Module](https://github.com/Hackndo/lsassy/tree/master/cme)

## Issues

If you find an issue with this tool (that's very plausible !), please

* Check that you're using the latest version
* Send as much details as possible.
    - For standalone **lsassy**, please use maximum verbosity `-vv`
    - For CME module, please use CrackMapExec `--verbose` flag

## Changelog

```
v2.1.0
------
* Kerberos authentication support (Thank you laxa for PR)
* Add CME module for python3
* Update bloodhound queries for BloodHound3
* Bug fixes

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

## Acknowledgments

* [Impacket](https://github.com/SecureAuthCorp/impacket)
* [SkelSec](http://twitter.com/skelsec) for Pypykatz, but also for his patience and help
* [mpgn](https://twitter.com/mpgn_x64) for his help and ideas

## Contributors

* [ITPPA](https://github.com/ITPPA/)
* [viaccoz](https://github.com/viaccoz)
* [blurbdust](https://github.com/blurbdust)
* [exploide](https://github.com/exploide)
* [Laxa](https://github.com/Laxa)
