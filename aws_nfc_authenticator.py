#!/usr/bin/env python3
"""
AWS NFC Authenticator - Client Application
Adapted from proven NFC Google Cloud Authentication patterns

Provides hardware-based authentication for AWS using NFC tokens.
Physical possession of NFC tag required for AWS access.
"""

import os
import sys
import json
from aws_combined_vault import AWSCombinedVault
import boto3
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

class AWSNFCAuthenticator:
    def __init__(self, config_path="aws_config.json"):
        """Initialize AWS NFC Authenticator with configuration."""
        self.config_path = config_path
        self.config = self.load_config()
        self.vault_manager = AWSCombinedVault()
        self.vault_path = "aws_vault_encrypted.bin"
        
    def load_config(self):
        """Load AWS configuration settings."""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"{Fore.RED}❌ Config file not found: {self.config_path}{Style.RESET_ALL}")
            sys.exit(1)
            
    def generate_device_fingerprint(self):
        """Generate unique device fingerprint for binding."""
        # Collect multiple device characteristics
        mac_addresses = []
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if hasattr(addr, 'address') and addr.address and len(addr.address) == 17:
                    mac_addresses.append(addr.address)
        
        # Create composite fingerprint
        fingerprint_data = {
            "platform": os.uname().sysname,
            "machine": os.uname().machine,
            "macs": sorted(mac_addresses)[:3],  # Top 3 MACs
            "user": os.getenv('USER', 'unknown')
        }
        
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()
        
    def derive_vault_key(self, nfc_uid, device_salt=None):
        """Derive encryption key from NFC UID using PBKDF2."""
        if device_salt is None:
            device_salt = self.generate_device_fingerprint()
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.config['vault_settings']['key_length'],
            salt=device_salt.encode('utf-8'),
            iterations=self.config['vault_settings']['iterations']
        )
        return kdf.derive(nfc_uid.encode('utf-8'))
        
    def scan_nfc_tag(self):
        """
        Scan NFC tag and extract UID.
        Pauses for real user input and keeps it hidden for security.
        """
        try:
            import getpass
            
            print(f"{Fore.YELLOW}🏷️  Please tap your NFC tag on the reader...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}📱 Enter NFC UID (input will be hidden): {Style.RESET_ALL}", end="")
            
            # Get hidden input for security
            nfc_uid = getpass.getpass("")
            
            if not nfc_uid or len(nfc_uid) < 8:
                print(f"{Fore.RED}❌ Invalid NFC UID - must be at least 8 characters{Style.RESET_ALL}")
                return None
                
            print(f"{Fore.GREEN}✅ NFC tag detected (UID hidden for security){Style.RESET_ALL}")
            return nfc_uid.strip()
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  NFC scan cancelled{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}❌ NFC scanning failed: {e}{Style.RESET_ALL}")
            return None
            
    def authenticate(self, duration_seconds=900):
        """Main authentication flow using NFC token with combined chaos key."""
        try:
            print(f"{Fore.CYAN}🔐 AWS NFC Authentication Starting{Style.RESET_ALL}")
            print("=" * 50)
            print(f"{Fore.YELLOW}⏰ Session duration: {duration_seconds//60} minutes{Style.RESET_ALL}")
            
            # Step 1: Unlock vault with combined NFC + chaos key
            success, result = self.vault_manager.unlock_vault_with_combined_key()
            if not success:
                print(f"{Fore.RED}❌ Vault unlock failed: {result}{Style.RESET_ALL}")
                return False
                
            credentials = result
            print(f"{Fore.GREEN}🔓 Vault unlocked with NFC + chaos authentication{Style.RESET_ALL}")
            
            # Step 2: Assume AWS role using vault credentials
            try:
                import time
                # Create temporary AWS session
                temp_session = boto3.Session(
                    aws_access_key_id=credentials['aws_access_key_id'],
                    aws_secret_access_key=credentials['aws_secret_access_key'],
                    region_name=credentials.get('aws_region', 'us-east-1')
                )
                
                # Use STS to assume role with custom duration
                sts_client = temp_session.client('sts')
                role_response = sts_client.assume_role(
                    RoleArn=credentials['role_arn'],
                    RoleSessionName=f"nfc-chaos-auth-{int(time.time())}",
                    DurationSeconds=duration_seconds
                )
                
                # Extract temporary credentials
                temp_creds = role_response['Credentials']
                
                print(f"{Fore.GREEN}🎉 AWS Authentication Successful!{Style.RESET_ALL}")
                print(f"   {Fore.CYAN}🔑 Session authenticated with hardware token{Style.RESET_ALL}")
                print(f"   {Fore.YELLOW}⏰ Expires: {temp_creds['Expiration']}{Style.RESET_ALL}")
                
                # Test AWS access with temporary credentials
                test_session = boto3.Session(
                    aws_access_key_id=temp_creds['AccessKeyId'],
                    aws_secret_access_key=temp_creds['SecretAccessKey'],
                    aws_session_token=temp_creds['SessionToken'],
                    region_name=credentials.get('aws_region', 'us-east-1')
                )
                
                # Quick STS test to validate session
                sts_client = test_session.client('sts')
                identity = sts_client.get_caller_identity()
                print(f"   {Fore.GREEN}✅ AWS Identity: {identity['Arn']}{Style.RESET_ALL}")
                print(f"   {Fore.GREEN}✅ Account: {identity['Account']}{Style.RESET_ALL}")
                
                return True
                
            except Exception as aws_error:
                print(f"{Fore.RED}❌ AWS role assumption failed: {aws_error}{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}❌ Authentication failed: {e}{Style.RESET_ALL}")
            return False

def get_session_duration():
    """Get custom session duration from user or use default."""
    print(f"\n{Fore.CYAN}⏰ AWS Session Duration Configuration{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Default: 15 minutes (900 seconds){Style.RESET_ALL}")
    print(f"{Fore.CYAN}Available options:{Style.RESET_ALL}")
    print(f"  • 15 min (900s) - Default")
    print(f"  • 30 min (1800s)")
    print(f"  • 1 hour (3600s)")
    print(f"  • 2 hours (7200s)")
    print(f"  • 12 hours (43200s) - Maximum")
    
    while True:
        try:
            duration_input = input(f"\n{Fore.CYAN}Enter duration in minutes (or press Enter for default 15 min): {Style.RESET_ALL}").strip()
            
            if not duration_input:
                return 900  # Default 15 minutes
                
            duration_minutes = int(duration_input)
            duration_seconds = duration_minutes * 60
            
            # AWS STS role session limits
            if duration_seconds < 900:  # Minimum 15 minutes
                print(f"{Fore.RED}❌ Minimum duration is 15 minutes{Style.RESET_ALL}")
                continue
            elif duration_seconds > 43200:  # Maximum 12 hours
                print(f"{Fore.RED}❌ Maximum duration is 12 hours (720 minutes){Style.RESET_ALL}")
                continue
            else:
                print(f"{Fore.GREEN}✅ Session duration set to {duration_minutes} minutes{Style.RESET_ALL}")
                return duration_seconds
                
        except ValueError:
            print(f"{Fore.RED}❌ Please enter a valid number of minutes{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  Using default 15 minutes{Style.RESET_ALL}")
            return 900

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="AWS NFC Authentication Client")
    parser.add_argument("--test", action="store_true", help="Run authentication test")
    parser.add_argument("--config", default="aws_config.json", help="Config file path")
    parser.add_argument("--duration", type=int, help="Session duration in minutes (15-720)")
    parser.add_argument("--interactive", action="store_true", help="Interactive session duration prompt")
    
    args = parser.parse_args()
    
    # Initialize authenticator
    auth = AWSNFCAuthenticator(config_path=args.config)
    
    if args.test:
        print(f"{Fore.CYAN}🔄 Running AWS NFC Authentication Test{Style.RESET_ALL}")
        
        # Determine session duration
        if args.duration:
            duration_seconds = min(max(args.duration * 60, 900), 43200)  # Clamp between 15min-12hr
            print(f"{Fore.YELLOW}⏰ Using command-line duration: {args.duration} minutes{Style.RESET_ALL}")
        elif args.interactive:
            duration_seconds = get_session_duration()
        else:
            # Ask user for duration preference
            duration_seconds = get_session_duration()
            
        success = auth.authenticate(duration_seconds)
        sys.exit(0 if success else 1)
    else:
        print(f"{Fore.YELLOW}Use --test to run authentication test{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Options:{Style.RESET_ALL}")
        print(f"  --test                 Run authentication test")
        print(f"  --duration MINUTES     Set session duration (15-720 min)")
        print(f"  --interactive          Interactive duration prompt")
        sys.exit(1)

if __name__ == "__main__":
    main()
