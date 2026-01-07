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
        # Ignore "rule does not exist" errors during cleanup
        if "Bad rule" not in str(e.stderr):
            logging.error(f"iptables error: {e.stderr.decode().strip()}")
        return False

def init_firewall_chains():
    """Initialize custom chains for ACLs."""
    # Create chains if they don't exist
    run_iptables(["-N", "VPN_ACL"])
    
    # Ensure VPN_ACL is hooked into FORWARD chain (at the top)
    # We use -C to check if rule exists, if not we add it
    if not run_iptables(["-C", "FORWARD", "-j", "VPN_ACL"]):
        run_iptables(["-I", "FORWARD", "1", "-j", "VPN_ACL"])

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
        # Block access to Private Networks
        for net in PRIVATE_NETWORKS:
            run_iptables(["-A", "VPN_ACL", "-s", ip, "-d", net, "-j", "DROP"])
        # Allow everything else (Internet)
        run_iptables(["-A", "VPN_ACL", "-s", ip, "-j", "ACCEPT"])

    elif profile == PROFILE_LAN_ONLY:
        # Allow access to Private Networks
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
