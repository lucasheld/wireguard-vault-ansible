# wireguard-vault-ansible

## requirements
- ansible

## install

### vault-server
1. Install debian on a host
1. Adjust the ip address in section `[vault-server]` inside the ansible inventory `inventory/hosts.ini` to the debian host ip
1. To configure the new vault-server, execute the following command
```bash
ansible-playbook setup-vault-server.yml -k -K -u <user> --become-method su
```

### vault-agents
1. Install debian on a host
1. Adjust the ip addresses in section `[vault-agents]` inside the ansible inventory `inventory/hosts.ini`. Append the new debian host ip and remove unused ip addresses.
1. To configure the new vault-agent, execute the following command
```bash
ansible-playbook setup-vault-agents.yml -k -K -u <user> --become-method su
```

Repeat these steps so that you have at least two agents that can communicate with each other through a wireguard tunnel.
