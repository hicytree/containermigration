#!/bin/bash 

COUNTER=0

while [ 1 ]; do

    echo Hello $COUNTER

    sleep 1

    let COUNTER=COUNTER+1 
    
done