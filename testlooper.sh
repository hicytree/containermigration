#!/bin/bash 

# or run command pgrep -f script-name in the terminal
echo "The PID for the process: $$"

COUNTER=0

while [ 1 ]; do

    echo Test $COUNTER

    sleep 1

    let COUNTER=COUNTER+1 
    
done