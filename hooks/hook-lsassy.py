from PyInstaller.utils.hooks import collect_submodules

"""
Note that output "table_output" has been removed. There's a bug regarding pyinstaller and 
rich library which prevents compiling lsassy if this lib is somehow imported.
"""
hiddenimports = (
    collect_submodules("lsassy.exec")
    + collect_submodules("lsassy.output")
    + collect_submodules("lsassy.dumpmethod")
)
hiddenimports.remove("lsassy.output.table_output")
hiddenimports.append("unicrypto.backends.pycryptodomex")
