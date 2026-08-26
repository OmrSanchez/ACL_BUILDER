import ipaddress
from cisco_ports_aliases import tcp_ports_named, udp_ports_named


def port_segment(operator, port):
    port = (port or "").strip()
    return f"{operator} {port}" if port else ""

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        print(f"This network passed IP address check: {ip_str}")
        return True
    except ValueError as e:
        print(e)
        return False

def check_text_mask(user_mask):
    # print(f"Check User Mask Reports: {user_mask}")
    mask_text = user_mask.lstrip("/")
    num = mask_text
    if mask_text.isdigit():
        print(f"Check User Mask Reports: This is a digit")
        if 0 <= int(num) <= 32:
            print(f"Check User Mask Reports: This digit falls in the correct range. 0 - 32")
            print("Mask passed validation")
            return True
        else:
            return False
    else:
        return False

def sanitize_address(ip_add, mask):
    ip_add = ip_add
    mask = mask
    if not mask:
        return f"{ip_add}"
    else:
        return f"{ip_add}/{mask}"

def finalize_network(network):
    print(f"Finalize Network Reports: Received network - {network}")
    net = ipaddress.ip_network(network, strict=False)
    print(f"Finalize Network Reports: {net.network_address}")
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    elif net.num_addresses == (2 ** 32):
        return "any"
    else:
        return f"{net.network_address} {net.hostmask}"

def is_compatible_port(port):
    if not port.isdigit():
        print("Port is not a digit")
        if port.lower() in udp_ports_named:
            print("Port in compatible list of udp ports")
            return True
        elif port.lower() in tcp_ports_named:
            print("Port in compatible list of tcp ports")
            return True
        else:
            return False
    else:
        if 1 <= int(port) <= 65535:
            return True
        else:
            return False


