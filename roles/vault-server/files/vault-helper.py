import re
import json
import uuid
import argparse
import requests
import subprocess


base_secret = "wireguard"

# default for new clients
network_id = "10.0.0"
listen_port = "51820"


class Vault(object):
    def __init__(self, address: str, token: str):
        self.address = address
        self.token = token
        self._session = self._create_session()
    
    def _create_session(self):
        session = requests.session()
        session.headers.update({
            "X-Vault-Token": self.token
        })
        return session

    def get_data(self, path: str):
        url = f"{self.address}/v1/{base_secret}/data/{path}"
        r = self._session.get(url)
        return r.json()["data"]["data"]

    def put_data(self, path: str, data: dict):
        url = f"{self.address}/v1/{base_secret}/data/{path}"
        payload = {
            "data": data,
            "options": {}
        }
        r = self._session.put(url, json=payload)
        return r.json()["data"]

    def get_list(self, path: str):
        url = f"{self.address}/v1/{base_secret}/metadata"
        if path:
            url += f"/{path}"
        url += "?list=true"
        r = self._session.get(url)
        try:
            keys = r.json()["data"]["keys"]
        except KeyError:
            keys = []
        return [key.rstrip("/") for key in keys]

    def del_data(self, path: str):
        url = f"{self.address}/v1/{base_secret}/metadata/{path}"
        r = self._session.delete(url)
        return r.status_code
    
    def put_policy(self, name: str, policy: str):
        url = f"{self.address}/v1/sys/policies/acl/{name}"
        payload = {
            "policy": policy
        }
        r = self._session.put(url, json=payload)
        return r.status_code

    def put_role(self, name: str, token_policies: str):
        url = f"{self.address}/v1/auth/approle/role/{name}"
        payload = {
            "token_policies": token_policies
        }
        r = self._session.put(url, json=payload)
        return r.status_code
    
    def get_role_id(self, role_name: str):
        url = f"{self.address}/v1/auth/approle/role/{role_name}/role-id"
        r = self._session.get(url)
        return r.json()["data"]
    
    def put_role_secret_id(self, role_name: str):
        url = f"{self.address}/v1/auth/approle/role/{role_name}/secret-id"
        r = self._session.put(url)
        return r.json()["data"]


class Wireguard(object):
    @staticmethod
    def gen_private_key():
        return subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()

    @staticmethod
    def gen_public_key(private_key: str):
        return subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode("utf-8").strip()

    @staticmethod
    def gen_preshared_key():
        return subprocess.check_output("wg genpsk", shell=True).decode("utf-8").strip()


def next_num(nums: list, start: int = 1):
    num = start
    while num in nums:
        num += 1
    return num


def get_element_by_data(vault: Vault, elements: list, element_path: str, data: dict):
    for element in elements:
        element_data = vault.get_data(f"{element_path}/{element}")
        data_is_subset = data.items() <= element_data.items()
        if data_is_subset:
            return {
                "name": element,
                "data": element_data
            }


def gen_uuid():
    return uuid.uuid4().hex


def sync_peers(vault: Vault):
    clients = vault.get_list("")
    for client1 in clients:
        peers = vault.get_list(f"{client1}/peers")
        used_peers = []

        for client2 in clients:
            if client2 != client1:
                interface = vault.get_data(f"{client2}/interface")
                meta = vault.get_data(f"{client2}/meta")

                allowed_ips = interface["Address"].split("/")[0] + "/32"
                endpoint = meta["Address"] + ":" + interface["ListenPort"]
                private_key = interface["PrivateKey"]
                public_key = Wireguard.gen_public_key(private_key)

                element = get_element_by_data(vault, peers, f"{client1}/peers", {"Endpoint": endpoint})
                if element:
                    peer_name = element["name"]
                    peer_data = element["data"]
                else:
                    peer_name = gen_uuid()
                    peer_data = {}
                used_peers.append(peer_name)
                
                peer_data_old = peer_data.copy()
                peer_data.update({
                    "AllowedIPs": allowed_ips,
                    "Endpoint": endpoint,
                    "PublicKey": public_key
                })

                if peer_data != peer_data_old:
                    vault.put_data(f"{client1}/peers/{peer_name}", peer_data)

        # remove unused peers
        for peer in peers:
            if peer not in used_peers:
                vault.del_data(f"{client1}/peers/{peer}")


def get_client_by_external_ip(vault: Vault, clients: list, external_ip: str):
    for client in clients:
        meta = vault.get_data(f"{client}/meta")
        if meta["Address"] == external_ip:
            return client


def gen_new_internal_ip(vault: Vault, clients: list):
    interface_address_host_ids = []
    for client in clients:
        interface = vault.get_data(f"{client}/interface")
        address = interface["Address"]
        match = re.search(r'\d+\.\d+\.\d+\.(\d+)/24', address)
        host_id = int(match.group(1))
        interface_address_host_ids.append(host_id)
    new_host_id = next_num(interface_address_host_ids)
    internal_ip = f"{network_id}.{new_host_id}/24"
    return internal_ip


def add_client(vault: Vault, external_ip: str):
    clients = vault.get_list("")

    client = get_client_by_external_ip(vault, clients, external_ip)
    if not client:
        client = gen_uuid()
        internal_ip = gen_new_internal_ip(vault, clients)
        private_key = Wireguard.gen_private_key()

        vault.put_data(f"{client}/interface", {
            "Address": internal_ip,
            "ListenPort": listen_port,
            "PrivateKey": private_key
        })

        vault.put_data(f"{client}/meta", {
            "Address": external_ip
        })

    policy_name = role_name = f"{base_secret}-{client}"
    policy = """
    path \"""" + base_secret + """/data/""" + client + """/*\" {
        capabilities = [\"read\"]
    }
    path \"""" + base_secret + """/metadata/""" + client + """/*\" {
        capabilities = [\"read\", \"list\"]
    }
    """
    vault.put_policy(policy_name, policy)

    vault.put_role(role_name, policy_name)

    role_id = vault.get_role_id(role_name)["role_id"]
    secret_id = vault.put_role_secret_id(role_name)["secret_id"]

    print(json.dumps({
        "name": client,
        "role_id": role_id,
        "secret_id": secret_id
    }))


def remove_client(vault: Vault, client: str):
    vault.del_data(f"{client}/interface")
    
    vault.del_data(f"{client}/meta")

    peers = vault.get_list(f"{client}/peers")
    for peer in peers:
        vault.del_data(f"{client}/peers/{peer}")


def remove_clients(vault: Vault, mode: str, client_ips: list):
    if mode not in ["include", "exclude"]:
        raise ValueError(f"unknown mode {mode}")
    
    clients = vault.get_list("")
    for client in clients:
        meta = vault.get_data(f"{client}/meta")
        external_ip = meta["Address"]

        if mode == "include" and external_ip in client_ips:
            print(f"removing client {client} with external ip {external_ip}")
            remove_client(vault, client)
        
        if mode == "exclude" and external_ip not in client_ips:
            print(f"removing client {client} with external ip {external_ip}")
            remove_client(vault, client)


def rotate_key_pairs(vault: Vault):
    clients = vault.get_list("")
    for client in clients:
        private_key = Wireguard.gen_private_key()
        interface = vault.get_data(f"{client}/interface")
        interface.update({
            "PrivateKey": private_key
        })
        vault.put_data(f"{client}/interface", interface)


def rotate_preshared_keys(vault: Vault, overwrite: bool = True):
    paths_same_peers = []

    # write tuple of peer paths to paths_same_peers that needs the same preshares keys
    clients = vault.get_list("")
    for client1 in clients:
        client1_interface = vault.get_data(f"{client1}/interface")
        client1_meta = vault.get_data(f"{client1}/meta")
        client1_peers = vault.get_list(f"{client1}/peers")
        client1_endpoint = client1_meta["Address"] + ":" + client1_interface["ListenPort"]
        
        for client2 in clients:
            if client2 != client1:
                client2_peers = vault.get_list(f"{client2}/peers")
                for client2_peer in client2_peers:
                    client2_peer_data = vault.get_data(f"{client2}/peers/{client2_peer}")
                    client2_peer_endpoint = client2_peer_data["Endpoint"]

                    # the client2 peer must have the same endpoint as the client1 <external_ip>:<ListenPort>
                    if client2_peer_endpoint == client1_endpoint:
                        
                        # choose client1 peer with the same endpoint as the client2 <external_ip>:<ListenPort>
                        client_peer = None
                        for client1_peer in client1_peers:
                            client2_interface = vault.get_data(f"{client2}/interface")
                            client2_meta = vault.get_data(f"{client2}/meta")
                            client2_endpoint = client2_meta["Address"] + ":" + client2_interface["ListenPort"]

                            client1_peer_data = vault.get_data(f"{client1}/peers/{client1_peer}")
                            client1_peer_endpoint = client1_peer_data["Endpoint"]

                            if client2_endpoint == client1_peer_endpoint:
                                client_peer = client1_peer
                                break
                        
                        # then those peers gets the same preshared keys
                        paths_same_peers.append((f"{client1}/peers/{client_peer}", f"{client2}/peers/{client2_peer}"))

    # combine unidirectional {(p1, p2), (p2, p1)} to bidirectional edges {(p1, p2)}
    paths_same_peers_bidirectional = []
    for p1, p2 in paths_same_peers:
        if (p1, p2) not in paths_same_peers_bidirectional and (p2, p1) not in paths_same_peers_bidirectional:
            paths_same_peers_bidirectional.append((p1, p2))
    
    # write the same preshared key to peer1 and peer2
    for path_peer1, path_peer2 in paths_same_peers_bidirectional:
        preshared_key = Wireguard.gen_preshared_key()

        peer1_data = vault.get_data(path_peer1)
        peer2_data = vault.get_data(path_peer2)

        if not overwrite:
            peer1_preshared_key = peer1_data.get("PresharedKey")
            peer2_preshared_key = peer2_data.get("PresharedKey")
            if peer1_preshared_key and peer2_preshared_key and peer1_preshared_key == peer2_preshared_key:
                continue

        peer1_data.update({
            "PresharedKey": preshared_key
        })
        vault.put_data(path_peer1, peer1_data)

        peer2_data.update({
            "PresharedKey": preshared_key
        })
        vault.put_data(path_peer2, peer2_data)


def get_args():
    parser = argparse.ArgumentParser(description="wireguard vault helper")
    parser.add_argument("--vault-addr", default="https://127.0.0.1:8200", help="vault address")
    parser.add_argument("--vault-token", help="vault token")
    subparsers = parser.add_subparsers(dest="subparser_name")

    parser_add_client = subparsers.add_parser("add-client", help="add a new wireguard client")
    parser_add_client.add_argument("--host-ip", type=str, required=True, help="host ip address of the new client")

    parser_rm_client = subparsers.add_parser("rm-client", help="remove an existing wireguard client")
    parser_rm_client.add_argument("--include", type=str, nargs='*', help="host ip addresses of clients to be be removed")
    parser_rm_client.add_argument("--exclude", type=str, nargs='*', help="host ip addresses of clients to be be excluded from removal")

    subparsers.add_parser("sync-peers", help="sync wireguard client peers")

    subparsers.add_parser("rotate-key-pairs", help="rotate key pairs of existing wireguard clients")

    subparsers.add_parser("rotate-preshared-keys", help="rotate preshared keys of existing wireguard clients")

    args = parser.parse_args()
    return args


def main():
    args = get_args()

    vault = Vault(args.vault_addr, args.vault_token)
    
    if args.subparser_name == "add-client":
        add_client(vault, args.host_ip)
        sync_peers(vault)
        rotate_preshared_keys(vault, overwrite=False)
    if args.subparser_name == "rm-client":
        if args.include:
            remove_clients(vault, "include", args.include)
            sync_peers(vault)
        elif args.exclude:
            remove_clients(vault, "exclude", args.exclude)
            sync_peers(vault)
    if args.subparser_name == "sync-peers":
        sync_peers(vault)
        rotate_preshared_keys(vault, overwrite=False)
    if args.subparser_name == "rotate-key-pairs":
        rotate_key_pairs(vault)
        sync_peers(vault)
    if args.subparser_name == "rotate-preshared-keys":
        rotate_preshared_keys(vault)


if __name__ == "__main__":
    main()
