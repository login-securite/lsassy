#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

smbserver.py -username test -password t3st -ip 127.0.0.1 C$ ./share &> /dev/null &

echo -n "[TEST] Connexion error : "
RESULT=$(lsassy -j 'test:t3st@192.254.254.254' 2>&1)
RET=$(echo "$RESULT" | grep -c 'Connexion error')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Authentication error : "
RESULT=$(lsassy -j 'test:test@127.0.0.1' 2>&1)
RET=$(echo "$RESULT" | grep -c 'Authentication error')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Error opening share : "
RESULT=$(lsassy -j 'test:t3st@127.0.0.1' --dumppath "E\$/Windows/Temp" 2>&1)
RET=$(echo "$RESULT" | grep -c 'Error opening share')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Error opening file : "
RESULT=$(lsassy -j 'test:t3st@127.0.0.1' --dumppath "C\$/Windws/Temp" 2>&1)
RET=$(echo "$RESULT" | grep -c 'Error opening file')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi


echo -n "[TEST] Method not supported : "
RESULT=$(lsassy -j 'test:t3st@127.0.0.1' -m 99 --timeout 1 2>&1)
RET=$(echo "$RESULT" | grep -c 'Method not supported')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi


echo -n "[TEST] Parse remote dump : "
RESULT=$(lsassy -j 'test:t3st@127.0.0.1' --dumppath "C\$/lsass.dmp" 2>&1)
RET=$(echo "$RESULT" | grep -c 'Password')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

kill $!