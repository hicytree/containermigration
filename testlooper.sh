#!/bin/bash 

COUNTER=0

while [ 1 ]; do

    echo Test $COUNTER

    sleep 1

    let COUNTER=COUNTER+1 
    
done