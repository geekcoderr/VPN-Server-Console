"""
Firewall Manager for GeekSTunnel (ACLs).
Manages iptables rules to enforce user access policies.
"""
import subprocess
import logging

# ACL Profiles
PROFILE_FULL = "full"
PROFILE_INTERNET_ONLY = "internet-only"
PROFILE_INTRANET_ONLY = "intranet-only"

# Private Ranges (RFC 1918)
PRIVATE_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]

def run_iptables(args):
    """Run an iptables command."""
    cmd = ["iptables"] + args
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode().strip()
        # Ignore common errors during cleanup or initialization for idempotency
        ignore_msgs = [
            "Bad rule",             # Rule doesn't exist during deletion
            "Chain already exists", # Chain already exists during creation
            "already exists"        # Generic already exists
        ]
        if not any(msg in stderr for msg in ignore_msgs):
            logging.error(f"iptables error: {stderr}")
        return False

def run_ip6tables(args):
    """Run an ip6tables command."""
    cmd = ["ip6tables"] + args
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

def init_firewall_chains():
    """Initialize custom chains and DNS enforcement."""
    from .config import WG_INTERFACE, VPN_SERVER_IP
    
    # 1. Create chains if they don't exist
    run_iptables(["-N", "VPN_ACL"])
    
    # 2. Hook VPN_ACL into FORWARD chain
    if not run_iptables(["-C", "FORWARD", "-j", "VPN_ACL"]):
        run_iptables(["-I", "FORWARD", "1", "-j", "VPN_ACL"])

    # 2b. Allow established/related traffic (Stateful Inspection)
    # This is CRITICAL for return traffic from the internet
    if not run_iptables(["-C", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]):
        run_iptables(["-I", "FORWARD", "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

    # 2c. Enable NAT (Masquerade) for Internet Access
    # We use a generic rule for the VPN subnet. This is essential for internet access.
    if not run_iptables(["-t", "nat", "-C", "POSTROUTING", "-s", "10.50.0.0/24", "-j", "MASQUERADE"]):
        run_iptables(["-t", "nat", "-A", "POSTROUTING", "-s", "10.50.0.0/24", "-j", "MASQUERADE"])

    # 2d. MSS Clamping (MTU Fix)
    # This is CRITICAL for WireGuard. It prevents websites from hanging due to MTU issues.
    mss_rule = ["-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]
    if not run_iptables(["-t", "mangle", "-C", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]):
        run_iptables(mss_rule)
        print("🛡️  MSS Clamping enabled to prevent MTU-related website hangs.")

    # 3. DNS Enforcement (Network-Level Hijacking)
    # Force ALL port 53 traffic from VPN interface to our internal CoreDNS
    for proto in ["udp", "tcp"]:
        # Use -I 1 to ensure it's the absolute first rule in PREROUTING
        dnat_rule = ["-t", "nat", "-I", "PREROUTING", "1", "-i", WG_INTERFACE, "-p", proto, "--dport", "53", "-j", "DNAT", "--to-destination", f"{VPN_SERVER_IP}:53"]
        run_iptables(dnat_rule)
        
        # 3b. Allow DNS traffic in INPUT chain (since it's now destined for the server itself)
        # Use -I 1 to ensure it's not blocked by other INPUT rules
        input_rule = ["-I", "INPUT", "1", "-i", WG_INTERFACE, "-p", proto, "--dport", "53", "-d", VPN_SERVER_IP, "-j", "ACCEPT"]
        run_iptables(input_rule)

    # 3c. Block ANY DNS traffic in FORWARD chain that escaped hijacking
    # This is the fail-safe: if someone tries to use 8.8.8.8 and DNAT somehow fails, we DROP it.
    for proto in ["udp", "tcp"]:
        run_iptables(["-I", "FORWARD", "1", "-i", WG_INTERFACE, "-p", proto, "--dport", "53", "-j", "REJECT"])

    # 4. Block DNS-over-TLS (DoT) - Port 853
    # This forces devices to fall back to standard DNS (port 53) which we hijack
    dot_rule = ["-I", "FORWARD", "1", "-i", WG_INTERFACE, "-p", "tcp", "--dport", "853", "-j", "REJECT"]
    run_iptables(dot_rule)

    # 5. Block IPv6 DNS (Leaks)
    for proto in ["udp", "tcp"]:
        run_ip6tables(["-I", "FORWARD", "1", "-i", WG_INTERFACE, "-p", proto, "--dport", "53", "-j", "DROP"])

    # 6. Block Known DoH Provider IPs (Anti-Bypass)
    # Blocking port 443 to these IPs forces browsers to fall back to standard DNS
    DOH_IPS = [
        "8.8.8.8", "8.8.4.4",    # Google
        "1.1.1.1", "1.0.0.1",    # Cloudflare
        "9.9.9.9", "149.112.112.112" # Quad9
    ]
    for ip in DOH_IPS:
        run_iptables(["-I", "FORWARD", "1", "-i", WG_INTERFACE, "-d", ip, "-p", "tcp", "--dport", "443", "-j", "REJECT"])
        run_iptables(["-I", "FORWARD", "1", "-i", WG_INTERFACE, "-d", ip, "-p", "udp", "--dport", "443", "-j", "REJECT"])

def apply_acl(ip: str, profile: str):
    """
    Apply ACL rules for a specific User IP.
    """
    from .config import VPN_SERVER_IP
    # 1. Cleanup existing rules for this IP
    remove_acl(ip)

    if profile == PROFILE_FULL:
        # Full Access: Explicitly ACCEPT everything for this IP
        run_iptables(["-A", "VPN_ACL", "-s", ip, "-j", "ACCEPT"])

    elif profile == PROFILE_INTERNET_ONLY:
        # Internet Only: Block access to Private Networks (Intranet)
        # We don't need to allow VPN_SERVER_IP here because DNS is handled in INPUT chain
        for net in PRIVATE_NETWORKS:
            # Exception: Allow traffic to the VPN server IP itself (for dashboard/API if needed)
            # But block the rest of the private range
            run_iptables(["-A", "VPN_ACL", "-s", ip, "-d", VPN_SERVER_IP, "-j", "ACCEPT"])
            run_iptables(["-A", "VPN_ACL", "-s", ip, "-d", net, "-j", "DROP"])
        # Allow everything else (Internet)
        run_iptables(["-A", "VPN_ACL", "-s", ip, "-j", "ACCEPT"])

    elif profile == PROFILE_INTRANET_ONLY:
        # Intranet Only: Allow access to Private Networks, block Internet
        for net in PRIVATE_NETWORKS:
            run_iptables(["-A", "VPN_ACL", "-s", ip, "-d", net, "-j", "ACCEPT"])
        # Block everything else (Internet)
        run_iptables(["-A", "VPN_ACL", "-s", ip, "-j", "DROP"])

def remove_acl(ip: str):
    """Remove all ACL rules for a specific IP."""
    # Delete all rules matching this source IP in the VPN_ACL chain
    # We use a loop because -D only deletes one instance
    while run_iptables(["-D", "VPN_ACL", "-s", ip, "-j", "ACCEPT"]): pass
    while run_iptables(["-D", "VPN_ACL", "-s", ip, "-j", "DROP"]): pass
    while run_iptables(["-D", "VPN_ACL", "-s", ip, "-j", "REJECT"]): pass
    for net in PRIVATE_NETWORKS:
        while run_iptables(["-D", "VPN_ACL", "-s", ip, "-d", net, "-j", "DROP"]): pass
        while run_iptables(["-D", "VPN_ACL", "-s", ip, "-d", net, "-j", "ACCEPT"]): pass
