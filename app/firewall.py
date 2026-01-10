"""
Firewall Manager for GeekSTunnel (ACLs).
Manages iptables rules to enforce user access policies.
"""
import subprocess
import logging

# ACL Profiles
PROFILE_FULL = "full"
PROFILE_INTERNET_ONLY = "internet-only"
PROFILE_LAN_ONLY = "lan-only"

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

    # 3. DNS Enforcement (Hijacking)
    # Intercept port 53 traffic from VPN interface and redirect to internal CoreDNS
    # We use the 'nat' table PREROUTING chain
    for proto in ["udp", "tcp"]:
        dnat_rule = ["-t", "nat", "-A", "PREROUTING", "-i", WG_INTERFACE, "-p", proto, "--dport", "53", "-j", "DNAT", "--to-destination", f"{VPN_SERVER_IP}:53"]
        check_rule = ["-t", "nat", "-C", "PREROUTING", "-i", WG_INTERFACE, "-p", proto, "--dport", "53", "-j", "DNAT", "--to-destination", f"{VPN_SERVER_IP}:53"]
        
        if not run_iptables(check_rule):
            run_iptables(dnat_rule)
            print(f"🛡️  DNS Hijacking enabled for {proto} (forced to {VPN_SERVER_IP})")

    # 4. Block DNS-over-TLS (DoT) - Port 853
    # This forces devices to fall back to standard DNS (port 53) which we hijack
    dot_rule = ["-A", "VPN_ACL", "-i", WG_INTERFACE, "-p", "tcp", "--dport", "853", "-j", "DROP"]
    if not run_iptables(["-C", "VPN_ACL", "-i", WG_INTERFACE, "-p", "tcp", "--dport", "853", "-j", "DROP"]):
        run_iptables(dot_rule)
        print("🛡️  DNS-over-TLS (Port 853) blocked to prevent bypass.")

    # 5. Block IPv6 DNS (Leaks)
    # We don't support IPv6 DNS filtering yet, so we block it to force IPv4 fallback
    for proto in ["udp", "tcp"]:
        run_ip6tables(["-A", "FORWARD", "-i", WG_INTERFACE, "-p", proto, "--dport", "53", "-j", "DROP"])

def apply_acl(ip: str, profile: str):
    """
    Apply ACL rules for a specific User IP.
    
    Logic:
    1. Clear existing rules for this IP in VPN_ACL chain.
    2. Add new rules based on profile.
    """
    # 1. Cleanup existing rules for this IP
    # Note: iptables doesn't have a "delete all for IP" command easily.
    # We will just append new rules. Ideally, we should flush the chain and rebuild all,
    # but for now, we'll assume the caller handles state or we rely on the fact that
    # we are adding specific ACCEPT/DROP rules.
    
    # BETTER APPROACH: Delete specific rules for this IP first
    # This is tricky without a complex manager. 
    # For MVP: We will assume this function is called on startup/update.
    # To be safe, we try to delete potential existing rules for this IP.
    remove_acl(ip)

    if profile == PROFILE_FULL:
        # Full Access: Default is usually ACCEPT in FORWARD if not blocked.
        # But if we have a default DROP policy, we need to ACCEPT.
        # For now, we assume default FORWARD is ACCEPT or handled by other rules.
        # We explicitly ACCEPT everything for this IP to be safe.
        run_iptables(["-A", "VPN_ACL", "-s", ip, "-j", "ACCEPT"])

    elif profile == PROFILE_INTERNET_ONLY:
        # Internet Only: Block access to Private Networks (LAN)
        for net in PRIVATE_NETWORKS:
            run_iptables(["-A", "VPN_ACL", "-s", ip, "-d", net, "-j", "DROP"])
        # Allow everything else (Internet)
        run_iptables(["-A", "VPN_ACL", "-s", ip, "-j", "ACCEPT"])

    elif profile == PROFILE_LAN_ONLY:
        # LAN Only: Allow access to Private Networks, block Internet
        for net in PRIVATE_NETWORKS:
            run_iptables(["-A", "VPN_ACL", "-s", ip, "-d", net, "-j", "ACCEPT"])
        # Block everything else (Internet)
        run_iptables(["-A", "VPN_ACL", "-s", ip, "-j", "DROP"])

def remove_acl(ip: str):
    """Remove all ACL rules for a specific IP."""
    # We need to find and delete rules. 
    # Since we can't easily query, we blindly try to delete the rules we MIGHT have added.
    # This is brute-force but works for the 3 profiles we have.
    
    # 1. Delete ACCEPT all
    run_iptables(["-D", "VPN_ACL", "-s", ip, "-j", "ACCEPT"])
    
    # 2. Delete DROP all
    run_iptables(["-D", "VPN_ACL", "-s", ip, "-j", "DROP"])
    
    # 3. Delete Private Network rules (DROP/ACCEPT)
    for net in PRIVATE_NETWORKS:
        run_iptables(["-D", "VPN_ACL", "-s", ip, "-d", net, "-j", "DROP"])
        run_iptables(["-D", "VPN_ACL", "-s", ip, "-d", net, "-j", "ACCEPT"])
