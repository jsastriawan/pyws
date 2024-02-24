#!/bin/bash

if [[ $# -ne "1" ]]; 
then
    echo "Need one argument in a form of hostname:port"
    exit
fi
s=$1
host="${s%%:*}"
filename=$host".pem"

openssl s_client -showcerts -connect 192.168.1.15:16993 </dev/null 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' 
