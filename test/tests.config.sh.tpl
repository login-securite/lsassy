# COPY THIS FILE TO ./test.config.sh BEFORE USING tests_dev.sh

# User with admin rights on IP_OK
DOMAIN_ADMIN="domain/Administrator:P4ssw0rd"

# User without admin rights on IP_OK
USER="domain/jdoe:password"

# IP where -m 1 works
IP_OK="10.10.10.1"

# Hostname of IP where -m 1 works
HOST_OK="APP01"

# IP where lsass is protected with PPL or AV or EDR  (empty to skip test)
IP_PROTECTED=""

# Local tools for dumping methods (empty to skip test)
PROCDUMP="/path/to/procdump.exe"
DUMPERT="/path/to/dumpert.exe"