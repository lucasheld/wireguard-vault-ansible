#!/bin/sh

export VAULT_ADDR="http://127.0.0.1:8200"

config=$(vault operator init -format json -key-shares=1 -key-threshold=1)

if [ $? -eq 0 ]
then
   echo "${config}" > /root/vault_keys
fi
