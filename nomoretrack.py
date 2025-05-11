#!/usr/bin/env python3


import os
import sys
import time
import yaml
import signal
import argparse
import logging
import requests
import subprocess
import threading
import re  
from pathlib import Path
from datetime import datetime, timedelta


__version__ = "1.0"


try:
    if os.geteuid() == 0 and os.path.exists('/var/log'):  
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('/var/log/nomoretrack.log')
            ]
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
except (PermissionError, OSError):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

logger = logging.getLogger("nomoretrack")

# Default blocklist sources
DEFAULT_BLOCKLISTS = [
    {
        "name": "StevenBlack Hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "format": "hosts",
        "category": "general"
    },
    {
        "name": "MVPS Hosts",
        "url": "https://winhelp2002.mvps.org/hosts.txt",
        "format": "hosts",
        "category": "general"
    },
    {
        "name": "AdAway Hosts",
        "url": "https://adaway.org/hosts.txt",
        "format": "hosts",
        "category": "ads"
    },
    {
        "name": "Disconnect Tracking",
        "url": "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
        "format": "domain",
        "category": "trackers"
    },
    {
        "name": "EasyPrivacy",
        "url": "https://easylist.to/easylist/easyprivacy.txt",
        "format": "adblock",
        "category": "privacy"
    },
    {
        "name": "URLhaus Malware",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "format": "hosts",
        "category": "malware"
    },
    {
        "name": "NoCoin Filter List",
        "url": "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
        "format": "hosts",
        "category": "cryptominers"
    },
    {
        "name": "DigitalSide Threat-Intel",
        "url": "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
        "format": "domain",
        "category": "malware"
    },
    {
        "name": "WindowsSpyBlocker",
        "url": "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
        "format": "hosts",
        "category": "telemetry"
    }
]

     
DEFAULT_CONFIG = {
    "general": {
        "enabled": True,
        "check_updates": True,
        "update_interval": 24,  # hours
        "dns_provider": "dnsmasq"  # dnsmasq or hosts-file
    },
    "blocklists": [
        {
            "name": "StevenBlack Hosts",
            "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "format": "hosts",
            "category": "general",
            "enabled": True
        },
        {
            "name": "MVPS Hosts",
            "url": "https://winhelp2002.mvps.org/hosts.txt",
            "format": "hosts",
            "category": "general",
            "enabled": True
        },
        {
            "name": "AdAway Hosts",
            "url": "https://adaway.org/hosts.txt",
            "format": "hosts",
            "category": "ads",
            "enabled": True
        },
        {
            "name": "Disconnect Tracking",
            "url": "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
            "format": "domain",
            "category": "trackers",
            "enabled": True
        },
        # Enhanced lists
        {
            "name": "EasyPrivacy",
            "url": "https://easylist.to/easylist/easyprivacy.txt",
            "format": "adblock",
            "category": "privacy",
            "enabled": True
        },
        {
            "name": "URLhaus Malware",
            "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
            "format": "hosts", 
            "category": "malware",
            "enabled": True
        },
        {
            "name": "NoCoin Filter List",
            "url": "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
            "format": "hosts",
            "category": "cryptominers",
            "enabled": True
        },
        {
            "name": "DigitalSide Threat-Intel",
            "url": "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
            "format": "domain",
            "category": "malware",
            "enabled": True
        },
        {
            "name": "WindowsSpyBlocker",
            "url": "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
            "format": "hosts",
            "category": "telemetry",
            "enabled": True
        }
    ],
    "categories": {
        "ads": True,
        "trackers": True,
        "malware": True,
        "privacy": True,
        "telemetry": True,
        "cryptominers": True,
        "general": True
    },
    "custom_entries": {
        "blocked": [],
        "allowed": []
    },
    "advanced": {
        "use_regex_filtering": False,
        "block_subdomains": True,
        "use_wildcard_blocking": False
    }
}

DNSMASQ_CONF = "/etc/dnsmasq.conf"
DNSMASQ_NOMORETRACK_CONF = "/etc/dnsmasq.d/nomoretrack.conf"
HOSTS_FILE = "/etc/hosts"
HOSTS_BACKUP = "/etc/hosts.nomoretrack-backup"

DEFAULT_CONFIG_DIR = "/etc/nomoretrack"
DEFAULT_DATA_DIR = "/var/lib/nomoretrack"
if os.geteuid() != 0:
    DEFAULT_CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")
    DEFAULT_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# Enhanced blocking utilities
def detect_dns_providers():
    """
    Detect available DNS providers on the system
    
    Returns:
        list: List of available DNS providers
    """
    providers = []
    
    try:
        result = subprocess.run(["which", "dnsmasq"], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
        if result.returncode == 0:
            providers.append("dnsmasq")
    except:
        pass
        
    if os.path.exists("/etc/hosts"):
        providers.append("hosts-file")
        
    try:
        result = subprocess.run(["which", "unbound"], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
        if result.returncode == 0:
            providers.append("unbound")
    except:
        pass
    
    return providers

def is_valid_domain(domain):
    """
    Check if a string is a valid domain name
    
    Args:
        domain: Domain to check
        
    Returns:
        bool: True if valid domain
    """
    pattern = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    return bool(pattern.match(domain))

def filter_valid_domains(domain_list):
    """
    Filter a list to keep only valid domains
    
    Args:
        domain_list: List of domains to filter
        
    Returns:
        list: List of valid domains
    """
    return [d for d in domain_list if is_valid_domain(d)]

class EnhancedBlocker:
    """Enhanced domain blocking functionality"""
    
    def __init__(self, config):
        """
        Initialize with configuration
        
        Args:
            config: Configuration dict from NoMoreTrack
        """
        self.config = config
        self.use_regex = config.get("advanced", {}).get("use_regex_filtering", False)
        self.block_subdomains = config.get("advanced", {}).get("block_subdomains", True)
        self.use_wildcards = config.get("advanced", {}).get("use_wildcard_blocking", False)
        
        self.compiled_patterns = []
        self.compiled_whitelist = []
    
    def process_adblock_format(self, file_path):
        """
        Process AdBlock format filter lists (like EasyPrivacy)
        
        Args:
            file_path: Path to the AdBlock format file
            
        Returns:
            list: List of domains to block
        """
        domains = set()
        
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                
                if not line or line.startswith('!') or line.startswith('['):
                    continue
                
                if '||' in line and '^' in line:
                    domain = line.split('||')[1].split('^')[0]
                    
                    if '*' in domain:
                        continue
                    
                    if '$' in domain:
                        domain = domain.split('$')[0]
                    
                    domain = domain.lower().strip()
                    if domain:
                        domains.add(domain)
        
        return domains
    
    def generate_regex_pattern(self, domain):
        """
        Generate a regex pattern for a domain
        
        Args:
            domain: Domain to generate pattern for
            
        Returns:
            str: Regex pattern string
        """
        if '*' in domain:
            pattern = domain.replace('.', r'\.').replace('*', r'.*')
            return f"^{pattern}$"
        else:
            return f"^{domain.replace('.', r'\.')}$"
    
    def is_domain_blocked(self, domain, blocked_domains, whitelist):
        """
        Check if a domain should be blocked
        
        Args:
            domain: Domain to check
            blocked_domains: Set of blocked domains
            whitelist: Set of whitelisted domains
            
        Returns:
            bool: True if domain should be blocked
        """
        if domain in whitelist:
            return False
            
        if domain in blocked_domains:
            return True
            
        if self.block_subdomains:
            domain_parts = domain.split('.')
            for i in range(1, len(domain_parts) - 1):
                parent_domain = '.'.join(domain_parts[i:])
                if parent_domain in blocked_domains:
                    return True
        
        if self.use_regex:
            for pattern in self.compiled_patterns:
                if pattern.match(domain):
                    for wl_pattern in self.compiled_whitelist:
                        if wl_pattern.match(domain):
                            return False
                    return True
                    
        return False
    
    def setup_regex_patterns(self, blocked_domains, whitelist):
        """
        Compile regex patterns for better performance
        
        Args:
            blocked_domains: Set of blocked domains
            whitelist: Set of whitelisted domains
        """
        self.compiled_patterns = []
        self.compiled_whitelist = []
        
        if self.use_regex:
            for domain in blocked_domains:
                if '*' in domain:
                    try:
                        pattern = self.generate_regex_pattern(domain)
                        self.compiled_patterns.append(re.compile(pattern))
                    except re.error:
                        continue
            
            for domain in whitelist:
                if '*' in domain:
                    try:
                        pattern = self.generate_regex_pattern(domain)
                        self.compiled_whitelist.append(re.compile(pattern))
                    except re.error:
                        continue
    
    def apply_hosts_blocking(self, blocked_domains, whitelist, hosts_file="/etc/hosts"):
        """
        Apply blocking via hosts file instead of DNS
        
        Args:
            blocked_domains: Set of domains to block
            whitelist: Set of domains to whitelist
            hosts_file: Path to hosts file
            
        Returns:
            bool: True if successful
        """
        try:
            with open(hosts_file, 'r') as f:
                hosts_content = f.readlines()
            
            clean_hosts = []
            skip_line = False
            for line in hosts_content:
                if "# --- NoMoreTrack START ---" in line:
                    skip_line = True
                    continue
                
                if "# --- NoMoreTrack END ---" in line:
                    skip_line = False
                    continue
                
                if not skip_line:
                    clean_hosts.append(line)
            
            with open(f"{hosts_file}.bak", 'w') as f:
                f.writelines(clean_hosts)
            
            filtered_domains = [d for d in blocked_domains if d not in whitelist]
            
            with open(hosts_file, 'w') as f:
                f.writelines(clean_hosts)
                
                f.write("\n# --- NoMoreTrack START ---\n")
                f.write(f"# Generated by NoMoreTrack: {len(filtered_domains)} domains\n")
                
                for domain in sorted(filtered_domains):
                    f.write(f"0.0.0.0 {domain}\n")
                
                f.write("# --- NoMoreTrack END ---\n")
            
            return True
        except Exception as e:
            print(f"Error applying hosts blocking: {e}")
            return False
    
    def apply_dns_blocking(self, blocked_domains, whitelist):
        """
        Apply blocking via dnsmasq
        
        Args:
            blocked_domains: Set of domains to block
            whitelist: Set of domains to whitelist
            
        Returns:
            bool: True if successful
        """

        return False


try:
    from enhanced_blocking import EnhancedBlocker, detect_dns_providers, is_valid_domain, filter_valid_domains
    ENHANCED_BLOCKING_AVAILABLE = True
except ImportError:
    ENHANCED_BLOCKING_AVAILABLE = True


ENHANCED_BLOCKING_AVAILABLE = True

class Config:
    """Configuration management class."""
    
    def __init__(self, config_path):
        """
        Args:
            config_path: Directory containing the configuration file
        """
        self.config_dir = Path(config_path)
        self.config_file = self.config_dir / "config.yaml"
        self.config = None
        
        os.makedirs(self.config_dir, exist_ok=True)
        
        self.load_config()
    
    def load_config(self):
        """Loads the configuration file or creates it with default values."""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    self.config = yaml.safe_load(f)
                logger.info(f"Configuration file loaded: {self.config_file}")
            except Exception as e:
                logger.error(f"Error loading configuration file: {e}")
                logger.info("Using default configuration")
                self.config = DEFAULT_CONFIG
        else:
            logger.info(f"Configuration file not found, using default values")
            self.config = DEFAULT_CONFIG
            self.save_config()
    
    def save_config(self):
        """Saves the configuration to a file."""
        try:
            with open(self.config_file, "w") as f:
                yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
            logger.info(f"Configuration file saved: {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration file: {e}")
            return False
    
    def get_config(self):
        """Returns the configuration."""
        return self.config
    
    def update_config(self, new_config):
        """Updates the configuration and saves it.
        
        Args:
            new_config: New configuration values
            
        Returns:
            bool: True if the update was successful
        """
        self.config = new_config
        return self.save_config()
    
    def get_enabled_blocklists(self):
        """Returns the enabled blocklists."""
        return [bl for bl in self.config["blocklists"] if bl.get("enabled", True)]
    
    def is_enabled(self):
        """Checks whether the blocking system is enabled."""
        return self.config["general"]["enabled"]
    
    def set_enabled(self, enabled):
        """Enables or disables the blocking system.
        
        Args:
            enabled: True to enable, False to disable
            
        Returns:
            bool: True if the operation was successful
        """
        self.config["general"]["enabled"] = enabled
        return self.save_config()
    
    def add_custom_block(self, domain):
        """Adds a domain to the custom block list.
        
        Args:
            domain: Domain to block
            
        Returns:
            bool: True if the operation was successful
        """
        if domain not in self.config["custom_entries"]["blocked"]:
            self.config["custom_entries"]["blocked"].append(domain)
            return self.save_config()
        return True
    
    def add_custom_allow(self, domain):
        """Adds a domain to the custom allow list.
        
        Args:
            domain: Domain to allow
            
        Returns:
            bool: True if the operation was successful
        """
        if domain not in self.config["custom_entries"]["allowed"]:
            self.config["custom_entries"]["allowed"].append(domain)
            return self.save_config()
        return True
    
    def remove_custom_block(self, domain):
        """Removes a domain from the custom block list.
        
        Args:
            domain: Domain to remove
            
        Returns:
            bool: True if the operation was successful
        """
        if domain in self.config["custom_entries"]["blocked"]:
            self.config["custom_entries"]["blocked"].remove(domain)
            return self.save_config()
        return True
    
    def remove_custom_allow(self, domain):
        """Removes a domain from the custom allow list.
        
        Args:
            domain: Domain to remove
            
        Returns:
            bool: True if the operation was successful
        """
        if domain in self.config["custom_entries"]["allowed"]:
            self.config["custom_entries"]["allowed"].remove(domain)
            return self.save_config()
        return True


class BlocklistManager:
    """Class that downloads and processes blocklists."""
    
    def __init__(self, config_dir, data_dir):
        """
        Args:
            config_dir: Directory containing configuration files
            data_dir: Directory where blocklists will be saved
        """
        self.config_dir = Path(config_dir)
        self.data_dir = Path(data_dir)
        self.blocklists_dir = self.data_dir / "blocklists"
        self.processed_file = self.data_dir / "hosts.blocked"
        self.stats = {
            "total_domains": 0,
            "by_category": {}
        }
        
        os.makedirs(self.blocklists_dir, exist_ok=True)
        os.makedirs(self.config_dir, exist_ok=True)
        
        self.enhanced_blocking = True
    
    def download_blocklist(self, name, url, format_type="hosts", category="general"):
        """Downloads a blocklist from the specified URL.
        
        Args:
            name: Name of the blocklist
            url: URL of the blocklist to download
            format_type: File format ('hosts', 'domain', or 'adblock')
            category: Category of the list (ads, trackers, etc.)
            
        Returns:
            bool: True if the download was successful
        """
        file_path = self.blocklists_dir / f"{name.lower().replace(' ', '_')}.txt"
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            with open(file_path, "w") as f:
                f.write(response.text)
            
            logger.info(f"Blocklist downloaded: {name} ({category})")
            return True
        except requests.RequestException as e:
            logger.error(f"Error downloading blocklist ({name}): {e}")
            return False
    
    def update_all_blocklists(self, blocklists=None, config=None):
        """Updates all blocklists.
        
        Args:
            blocklists: Blocklists to update. If None, default lists are used.
            config: Configuration dict
            
        Returns:
            bool: True if all lists were successfully updated
        """
        if blocklists is None:
            blocklists = DEFAULT_BLOCKLISTS
        
        self.stats = {
            "total_domains": 0,
            "by_category": {}
        }
        
        if config and "categories" in config:
            enabled_categories = [cat for cat, enabled in config["categories"].items() if enabled]
            blocklists = [bl for bl in blocklists if bl.get("category", "general") in enabled_categories]
        
        success = True
        for blocklist in blocklists:
            if not self.download_blocklist(
                blocklist["name"], 
                blocklist["url"], 
                blocklist.get("format", "hosts"),
                blocklist.get("category", "general")
            ):
                success = False
        
        if success:
            return self.process_blocklists(config)
        return False
    
    def process_adblock_format(self, file_path):
        """Process an AdBlock format filter list.
        
        Args:
            file_path: Path to the AdBlock filter list
            
        Returns:
            set: Set of domains to block
        """
        domains = set()
        
        try:
            with open(file_path, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    
                    if not line or line.startswith('!') or line.startswith('['):
                        continue
                    
                    if '||' in line and '^' in line:
                        domain = line.split('||')[1].split('^')[0]
                        
                        if '*' in domain:
                            continue
                        
                        if '$' in domain:
                            domain = domain.split('$')[0]
                        
                        domain = domain.lower().strip()
                        if domain and is_valid_domain(domain):
                            domains.add(domain)
        except Exception as e:
            logger.error(f"Error processing AdBlock format file {file_path}: {e}")
        
        return domains
    
    def process_blocklists(self, config=None):
        """Processes all downloaded blocklists to create a single hosts file.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            bool: True if the operation was successful
        """
        blocked_domains = set()
        allowed_domains = set()
        domains_by_category = {}
        
        if config and "custom_entries" in config:
            allowed_domains = set(config["custom_entries"]["allowed"])
        
        custom_blocked = set()
        if config and "custom_entries" in config:
            custom_blocked = set(config["custom_entries"]["blocked"])
        
        for file_path in self.blocklists_dir.glob("*.txt"):
            try:
                format_type = "hosts"  # default
                category = "general"   # default
                
                file_name = file_path.name
                for blocklist in DEFAULT_BLOCKLISTS:
                    bl_name = blocklist["name"].lower().replace(' ', '_') + ".txt"
                    if bl_name == file_name:
                        format_type = blocklist.get("format", "hosts")
                        category = blocklist.get("category", "general")
                        break
                
                if category not in domains_by_category:
                    domains_by_category[category] = set()
                
                if format_type == "adblock":
                    domain_set = self.process_adblock_format(file_path)
                    domains_by_category[category].update(domain_set)
                    blocked_domains.update(domain_set)
                else:
                    with open(file_path, "r", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            
                            # Skip comments and empty lines
                            if not line or line.startswith("#"):
                                continue
                            
                            # Parse hosts format lines
                            if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
                                parts = line.split()
                                if len(parts) >= 2:
                                    domain = parts[1].lower()
                                    if is_valid_domain(domain):
                                        blocked_domains.add(domain)
                                        domains_by_category[category].add(domain)
                            # Domain list format
                            else:
                                domain = line.lower()
                                if is_valid_domain(domain):
                                    blocked_domains.add(domain)
                                    domains_by_category[category].add(domain)
            except Exception as e:
                logger.error(f"Error processing blocklist ({file_path}): {e}")
        
        blocked_domains.update(custom_blocked)
        if "custom" not in domains_by_category:
            domains_by_category["custom"] = set()
        domains_by_category["custom"].update(custom_blocked)
        
        blocked_domains = blocked_domains - allowed_domains
        
        self.stats["total_domains"] = len(blocked_domains)
        for category, domains in domains_by_category.items():
            self.stats["by_category"][category] = len(domains - allowed_domains)
        
        try:
            with open(self.processed_file, "w") as f:
                f.write("# Created by NoMoreTrack\n")
                f.write(f"# Update date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Number of blocked domains: {len(blocked_domains)}\n")
                f.write("# Blocked domains by category:\n")
                
                for category, count in self.stats["by_category"].items():
                    f.write(f"#   {category}: {count} domains\n")
                
                f.write("\n")
                
                for domain in sorted(blocked_domains):
                    f.write(f"0.0.0.0 {domain}\n")
            
            logger.info(f"Blocklist created: {self.processed_file} ({len(blocked_domains)} domains)")
            return True
        except Exception as e:
            logger.error(f"Error creating blocklist: {e}")
            return False
    
    def get_processed_blocklist_path(self):
        """Returns the path of the processed blocklist file."""
        return str(self.processed_file)
    
    def get_last_update_time(self):
        """Returns the time of the last update.
        
        Returns:
            float: Last update time (epoch), None if no update
        """
        if self.processed_file.exists():
            return self.processed_file.stat().st_mtime
        return None
    
    def get_stats(self):
        """Returns the blocklist statistics.
        
        Returns:
            dict: Stats about blocked domains
        """
        return self.stats


# DNS functions
def create_backup_hosts():
    """Creates a backup of the current hosts file."""
    if not os.path.exists(HOSTS_BACKUP):
        try:
            subprocess.run(["cp", HOSTS_FILE, HOSTS_BACKUP], check=True)
            logger.info(f"Hosts file backup created: {HOSTS_BACKUP}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error creating hosts file backup: {e}")
            return False
    return True

def configure_dnsmasq(blocklist_path):
    """Configures dnsmasq to use the NoMoreTrack blocklist file."""
    

    if os.path.exists(DNSMASQ_CONF):
        with open(DNSMASQ_CONF, "r") as f:
            content = f.read()
            
        if "conf-dir=/etc/dnsmasq.d" not in content:
            with open(DNSMASQ_CONF, "a") as f:
                f.write("\n# Added by NoMoreTrack\nconf-dir=/etc/dnsmasq.d\n")
                logger.info("Added conf-dir directive to dnsmasq.conf")
    
    os.makedirs("/etc/dnsmasq.d", exist_ok=True)
    
    # Create dnsmasq configuration for NoMoreTrack
    with open(DNSMASQ_NOMORETRACK_CONF, "w") as f:
        f.write(f"# Created by NoMoreTrack\n")
        f.write(f"addn-hosts={blocklist_path}\n")
    
    logger.info(f"dnsmasq configuration updated: {DNSMASQ_NOMORETRACK_CONF}")
    return True

def restart_dns_service():
    """Restarts the DNS service."""
    try:
        result = subprocess.run(["systemctl", "is-active", "dnsmasq"], 
                               stdout=subprocess.PIPE, text=True)
        
        if result.stdout.strip() == "active":
            subprocess.run(["systemctl", "restart", "dnsmasq"], check=True)
            logger.info("dnsmasq service restarted")
        else:
            subprocess.run(["systemctl", "start", "dnsmasq"], check=True)
            logger.info("dnsmasq service started")
        
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error restarting DNS service: {e}")
        return False

def apply_blocklist(blocklist_path):
    """Applies the blocklist to the system DNS."""
    if not os.path.exists(blocklist_path):
        logger.error(f"Blocklist not found: {blocklist_path}")
        return False
    
    if not create_backup_hosts():
        return False
    
    if not configure_dnsmasq(blocklist_path):
        return False
    
    if not restart_dns_service():
        return False
    
    logger.info(f"Blocklist successfully applied: {blocklist_path}")
    return True

def disable_blocking():
    """Disables the blocking system and removes configurations."""
    if os.path.exists(DNSMASQ_NOMORETRACK_CONF):
        try:
            os.remove(DNSMASQ_NOMORETRACK_CONF)
            logger.info(f"NoMoreTrack DNS configuration removed")
            
            # Restart DNS service   
            restart_dns_service()
            return True
        except OSError as e:
            logger.error(f"Error removing DNS configuration: {e}")
            return False
    return True


class NoMoreTrackDaemon:
    """Main service class for NoMoreTrack running in the background."""
    
    def __init__(self, data_dir=DEFAULT_DATA_DIR, config_dir=DEFAULT_CONFIG_DIR):
        """
        Args:
            data_dir: Directory containing data files
            config_dir: Directory containing configuration files
        """
        self.data_dir = Path(data_dir)
        self.config_dir = Path(config_dir)
        self.running = False
        self.update_thread = None
        self.last_update = None
        
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.config_dir, exist_ok=True)
        
        self.config = Config(self.config_dir)
        self.blocklist_manager = BlocklistManager(self.config_dir, self.data_dir)
        
        self.enhanced_blocker = EnhancedBlocker(self.config.get_config())
        
        signal.signal(signal.SIGTERM, self.handle_signal)
        signal.signal(signal.SIGINT, self.handle_signal)
    
    def handle_signal(self, signum, frame):
        """Signal handler."""
        logger.info(f"Signal received: {signum}")
        self.stop()
    
    def start(self):
        """Starts the service."""
        if self.running:
            logger.warning("Service is already running")
            return
        
        logger.info("Starting NoMoreTrack service")
        self.running = True
        
        # Update blocklists on first run    
        if self.config.is_enabled():
            self.update_blocklists()

        self.update_thread = threading.Thread(target=self.update_loop)
        self.update_thread.daemon = True
        self.update_thread.start()
        
        logger.info("NoMoreTrack service started")
    
    def stop(self):
        """Stops the service."""
        if not self.running:
            return
        
        logger.info("Stopping NoMoreTrack service")
        self.running = False
        
        if self.update_thread:
            self.update_thread.join(timeout=5)
        
        logger.info("NoMoreTrack service stopped")
    
    def update_loop(self):
        """Loop that periodically updates blocklists."""
        while self.running:
            if self.config.is_enabled() and self.config.get_config()["general"]["check_updates"]:
                now = datetime.now()
                update_interval = self.config.get_config()["general"]["update_interval"]
                
                last_update_time = self.blocklist_manager.get_last_update_time()
                if last_update_time:
                    last_update = datetime.fromtimestamp(last_update_time)
                    next_update = last_update + timedelta(hours=update_interval)
                    
                    if now >= next_update:
                        logger.info(f"Starting scheduled update (last update: {last_update})")
                        self.update_blocklists()
                else:
                    logger.info("Starting first update")
                    self.update_blocklists()
            
            for _ in range(60):
                if not self.running:
                    return
                time.sleep(10)
    
    def update_blocklists(self):
        """Updates the blocklists and applies them to DNS."""
        if not self.config.is_enabled():
            logger.info("Blocking is disabled, skipping update")
            return False
        
        try:

            enabled_blocklists = self.config.get_enabled_blocklists()
            config = self.config.get_config()
            
            # Update lists
            if self.blocklist_manager.update_all_blocklists(enabled_blocklists, config):
                logger.info("Blocklists successfully updated")
                
             
                blocklist_path = self.blocklist_manager.get_processed_blocklist_path()
                

                if config["general"].get("dns_provider") == "hosts-file":

                    blocked_domains = set()
                    with open(blocklist_path, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                parts = line.split()
                                if len(parts) >= 2:
                                    blocked_domains.add(parts[1])
                    
                    whitelist = set(config["custom_entries"]["allowed"])
                    if self.enhanced_blocker.apply_hosts_blocking(blocked_domains, whitelist):
                        logger.info("Blocklist applied using hosts file")
                        self.last_update = datetime.now()
                        return True
                    else:
                        logger.error("Error applying blocklist using hosts file")
                        return False
                        
                if apply_blocklist(blocklist_path):
                    logger.info("Blocklist applied to system DNS")
                    self.last_update = datetime.now()
                    return True
            
            logger.error("Error updating blocklists")
            return False
            
        except Exception as e:
            logger.error(f"Unexpected error updating blocklists: {e}")
            return False
    
    def disable(self):
        """Disables the blocking system."""
        if not self.config.is_enabled():
            logger.info("Blocking is already disabled")
            return True
        
        logger.info("Disabling blocking system")
        
        self.config.set_enabled(False)
        
        config = self.config.get_config()
        if config["general"].get("dns_provider") == "hosts-file":
            # Apply empty list to clear hosts file  
            self.enhanced_blocker.apply_hosts_blocking(set(), set())
            logger.info("Hosts file blocking disabled")
            return True
        

        if disable_blocking():
            logger.info("Blocking system disabled")
            return True
        
        logger.error("Error disabling blocking system")
        return False
    
    def enable(self):
        """Enables the blocking system."""
        if self.config.is_enabled():
            logger.info("Blocking is already enabled")
            return True
        
        logger.info("Enabling blocking system")
        

        self.config.set_enabled(True)
        
   
        if self.update_blocklists():
            logger.info("Blocking system enabled")
            return True
        
        logger.error("Error enabling blocking system")
        self.config.set_enabled(False)  
        return False
    
    def add_custom_block(self, domain):
        """Adds a domain to the custom block list and updates lists."""
        if self.config.add_custom_block(domain):
            logger.info(f"Domain added to block list: {domain}")
            return self.update_blocklists()
        return False
    
    def add_custom_allow(self, domain):
        """Adds a domain to the custom allow list and updates lists."""
        if self.config.add_custom_allow(domain):
            logger.info(f"Domain added to allow list: {domain}")
            return self.update_blocklists()
        return False
    
    def remove_custom_block(self, domain):
        """Removes a domain from the custom block list and updates lists."""
        if self.config.remove_custom_block(domain):
            logger.info(f"Domain removed from block list: {domain}")
            return self.update_blocklists()
        return False
    
    def remove_custom_allow(self, domain):
        """Removes a domain from the custom allow list and updates lists."""
        if self.config.remove_custom_allow(domain):
            logger.info(f"Domain removed from allow list: {domain}")
            return self.update_blocklists()
        return False
    
    def get_blocking_stats(self):
        """Returns statistics about blocked domains."""
        return self.blocklist_manager.get_stats()
    
    def toggle_category(self, category, enabled):
        """Enable or disable a blocking category.
        
        Args:
            category: Category name
            enabled: True to enable, False to disable
            
        Returns:
            bool: True if successful
        """
        config = self.config.get_config()
        
        if "categories" not in config:
            config["categories"] = {}
        
        config["categories"][category] = enabled
        
        if self.config.update_config(config):
            logger.info(f"Category '{category}' {'enabled' if enabled else 'disabled'}")
            
            if not enabled and self.config.is_enabled():
                return self.update_blocklists()
            return True
        
        return False



def main():
    """Main command line application."""
    parser = argparse.ArgumentParser(description="NoMoreTrack - Telemetry and tracking blocking tool")
    
    parser.add_argument("--version", action="version", version=f"NoMoreTrack v{__version__}")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # start command
    start_parser = subparsers.add_parser("start", help="Start service")
    
    # stop command
    stop_parser = subparsers.add_parser("stop", help="Stop service")
    
    # status command
    status_parser = subparsers.add_parser("status", help="Show service status")
    
    # update command
    update_parser = subparsers.add_parser("update", help="Update blocklists")
    
    # enable command
    enable_parser = subparsers.add_parser("enable", help="Enable blocking system")
    
    # disable command
    disable_parser = subparsers.add_parser("disable", help="Disable blocking system")
    
    # block command
    block_parser = subparsers.add_parser("block", help="Block domain")
    block_parser.add_argument("domain", help="Domain to block")
    
    # allow command
    allow_parser = subparsers.add_parser("allow", help="Allow domain")
    allow_parser.add_argument("domain", help="Domain to allow")
    
    # unblock command
    unblock_parser = subparsers.add_parser("unblock", help="Remove domain block")
    unblock_parser.add_argument("domain", help="Domain to unblock")
    
    # unallow command
    unallow_parser = subparsers.add_parser("unallow", help="Remove domain allow")
    unallow_parser.add_argument("domain", help="Domain to unallow")
    
    # stats command
    stats_parser = subparsers.add_parser("stats", help="Show blocking statistics")
    
    # categories command
    categories_parser = subparsers.add_parser("categories", help="List or modify blocking categories")
    categories_parser.add_argument("--list", action="store_true", help="List all categories")
    categories_parser.add_argument("--enable", metavar="CATEGORY", help="Enable a category")
    categories_parser.add_argument("--disable", metavar="CATEGORY", help="Disable a category")
    
    # dns command
    dns_parser = subparsers.add_parser("dns", help="DNS blocking configuration")
    dns_parser.add_argument("--provider", choices=["dnsmasq", "hosts-file"], 
                          help="Set DNS blocking provider")
    

    advanced_parser = subparsers.add_parser("advanced", help="Advanced blocking configuration")
    advanced_parser.add_argument("--regex", action="store_true", dest="use_regex", 
                               help="Enable regex-based filtering")
    advanced_parser.add_argument("--no-regex", action="store_false", dest="use_regex", 
                               help="Disable regex-based filtering")
    advanced_parser.add_argument("--subdomains", action="store_true", dest="block_subdomains", 
                               help="Block subdomains of blocked domains")
    advanced_parser.add_argument("--no-subdomains", action="store_false", dest="block_subdomains", 
                               help="Don't block subdomains of blocked domains")
    advanced_parser.add_argument("--wildcards", action="store_true", dest="use_wildcards", 
                               help="Enable wildcard domain blocking")
    advanced_parser.add_argument("--no-wildcards", action="store_false", dest="use_wildcards", 
                               help="Disable wildcard domain blocking")
    
    args = parser.parse_args()
    

    system_commands = ["start", "stop", "update", "enable", "disable", "block", "allow", "unblock", "unallow"]
    if args.command in system_commands and os.geteuid() != 0:
        print("This command requires administrator (root) privileges.")
        sys.exit(1)
    
    if args.command:
        daemon = NoMoreTrackDaemon()
        
        if args.command == "start":
            daemon.start()
            print("NoMoreTrack service started.")
        
        elif args.command == "stop":
            daemon.stop()
            print("NoMoreTrack service stopped.")
        
        elif args.command == "status":
            config = daemon.config.get_config()
            status = "Enabled" if config["general"]["enabled"] else "Disabled"
            last_update = daemon.last_update or "No updates yet"
            
            print(f"NoMoreTrack Status: {status}")
            print(f"Last update: {last_update}")
            print(f"Blocklist update interval: {config['general']['update_interval']} hours")
            print(f"DNS provider: {config['general'].get('dns_provider', 'dnsmasq')}")
            print(f"Active blocklists: {len(daemon.config.get_enabled_blocklists())}")
            

            if "categories" in config:
                enabled_categories = [cat for cat, enabled in config["categories"].items() if enabled]
                print(f"Enabled categories: {', '.join(enabled_categories)}")
            
            print(f"Custom blocked domains: {len(config['custom_entries']['blocked'])}")
            print(f"Custom allowed domains: {len(config['custom_entries']['allowed'])}")
            

            if "advanced" in config:
                adv = config["advanced"]
                print("\nAdvanced settings:")
                print(f"  Use regex filtering: {adv.get('use_regex_filtering', False)}")
                print(f"  Block subdomains: {adv.get('block_subdomains', True)}")
                print(f"  Use wildcard blocking: {adv.get('use_wildcard_blocking', False)}")
        
        elif args.command == "update":
            if daemon.update_blocklists():
                print("Blocklists successfully updated.")
            else:
                print("Error updating blocklists.")
                sys.exit(1)
        
        elif args.command == "enable":
            if daemon.enable():
                print("Blocking system enabled.")
            else:
                print("Error enabling blocking system.")
                sys.exit(1)
        
        elif args.command == "disable":
            if daemon.disable():
                print("Blocking system disabled.")
            else:
                print("Error disabling blocking system.")
                sys.exit(1)
        
        elif args.command == "block":
            if daemon.add_custom_block(args.domain):
                print(f"Domain added to block list: {args.domain}")
            else:
                print(f"Error adding domain to block list: {args.domain}")
                sys.exit(1)
        
        elif args.command == "allow":
            if daemon.add_custom_allow(args.domain):
                print(f"Domain added to allow list: {args.domain}")
            else:
                print(f"Error adding domain to allow list: {args.domain}")
                sys.exit(1)
        
        elif args.command == "unblock":
            if daemon.remove_custom_block(args.domain):
                print(f"Domain removed from block list: {args.domain}")
            else:
                print(f"Error removing domain from block list: {args.domain}")
                sys.exit(1)
        
        elif args.command == "unallow":
            if daemon.remove_custom_allow(args.domain):
                print(f"Domain removed from allow list: {args.domain}")
            else:
                print(f"Error removing domain from allow list: {args.domain}")
                sys.exit(1)
        
        elif args.command == "stats":
            stats = daemon.get_blocking_stats()
            
            print(f"Total domains blocked: {stats['total_domains']}")
            print("\nBlocked domains by category:")
            
            for category, count in stats.get("by_category", {}).items():
                print(f"  {category}: {count} domains")
        
        elif args.command == "categories":
            config = daemon.config.get_config()
            
            if args.list:
                print("Available blocking categories:")
                for cat, enabled in config.get("categories", {}).items():
                    status = "enabled" if enabled else "disabled"
                    print(f"  {cat} - {status}")
            
            elif args.enable:
                if daemon.toggle_category(args.enable, True):
                    print(f"Category '{args.enable}' enabled.")
                else:
                    print(f"Error enabling category '{args.enable}'.")
                    sys.exit(1)
            
            elif args.disable:
                if daemon.toggle_category(args.disable, False):
                    print(f"Category '{args.disable}' disabled.")
                else:
                    print(f"Error disabling category '{args.disable}'.")
                    sys.exit(1)
            else:
                categories_parser.print_help()
        
        elif args.command == "dns":
            config = daemon.config.get_config()
            
            if args.provider:

                if "general" not in config:
                    config["general"] = {}
                
                config["general"]["dns_provider"] = args.provider
                
                if daemon.config.update_config(config):
                    print(f"DNS provider set to {args.provider}.")
                    print("Run 'update' command to apply changes.")
                else:
                    print("Error updating DNS provider setting.")
                    sys.exit(1)
            else:
                print(f"Current DNS provider: {config['general'].get('dns_provider', 'dnsmasq')}")
                print("\nAvailable providers:")
                
                providers = detect_dns_providers()
                for provider in providers:
                    print(f"  {provider}")
        
        elif args.command == "advanced":
            config = daemon.config.get_config()
            

            if "advanced" not in config:
                config["advanced"] = {}
            

            updated = False
            
            if args.use_regex is not None:
                config["advanced"]["use_regex_filtering"] = args.use_regex
                updated = True
            
            if args.block_subdomains is not None:
                config["advanced"]["block_subdomains"] = args.block_subdomains
                updated = True
            
            if args.use_wildcards is not None:
                config["advanced"]["use_wildcard_blocking"] = args.use_wildcards
                updated = True
            
            if updated:
                if daemon.config.update_config(config):
                    print("Advanced settings updated.")
                    print("Run 'update' command to apply changes.")
                else:
                    print("Error updating advanced settings.")
                    sys.exit(1)
            else:
                adv = config.get("advanced", {})
                print("Advanced blocking settings:")
                print(f"  Use regex filtering: {adv.get('use_regex_filtering', False)}")
                print(f"  Block subdomains: {adv.get('block_subdomains', True)}")
                print(f"  Use wildcard blocking: {adv.get('use_wildcard_blocking', False)}")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main() 
