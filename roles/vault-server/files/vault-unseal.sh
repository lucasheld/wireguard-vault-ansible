#!/bin/sh

config=$(cat /root/vault_keys)

root_token=$(echo "${config}" | jq -r .root_token)
unseal_key=$(echo "${config}" | jq -r '.unseal_keys_b64[0]')

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="${root_token}"
vault operator unseal "${unseal_key}"
