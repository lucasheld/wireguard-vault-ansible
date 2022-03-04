#!/bin/sh

config=$(cat /root/vault_keys)
root_token=$(echo "${config}" | jq -r .root_token)

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="${root_token}"

# enable key-value store wireguard if it does not exist
vault secrets list | awk $1 'NR>2 {print $1}' | grep -q '^wireguard/$' || \
    vault secrets enable -version=2 -path wireguard kv

# enable auth approle if it does not exist
vault auth list | awk $1 'NR>2 {print $1}' | grep -q '^approle/$' || \
    vault auth enable approle
