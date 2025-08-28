#!/usr/bin/env python3
"""
AWS Vault Manager - Credential Encryption/Decryption
Adapted from proven NFC Google Cloud Authentication patterns

Manages encrypted AWS credential vaults using NFC-derived keys.
"""

import os
import json
import hashlib
import psutil
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from colorama import init, Fore, Style

# Initialize colorama for colored output
init()

class AWSVaultManager:
    def __init__(self, config_path="aws_config.json", vault_path="aws_vault_encrypted.bin"):
        """Initialize AWS Vault Manager."""
        self.config_path = config_path
        self.vault_path = vault_path
        self.config = self.load_config()
        
    def load_config(self):
        """Load vault configuration settings."""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Default config if file doesn't exist
            return {
                'vault_settings': {
                    'iterations': 100000,
                    'algorithm': 'PBKDF2-SHA256',
                    'key_length': 32
                }
            }
            
    def generate_device_fingerprint(self):
        """Generate unique device fingerprint for salt."""
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
            iterations=self.config['vault_settings']['iterations'],
            backend=default_backend()
        )
        return kdf.derive(nfc_uid.encode('utf-8'))
        
    def encrypt_credentials(self, credentials, nfc_uid):
        """Encrypt AWS credentials to vault using NFC-derived key."""
        try:
            # Validate credentials format
            required_fields = ['aws_access_key_id', 'aws_secret_access_key']
            for field in required_fields:
                if field not in credentials:
                    raise ValueError(f"Missing required credential field: {field}")
                    
            # Generate device salt and derive key
            device_salt = self.generate_device_fingerprint()
            key = self.derive_vault_key(nfc_uid, device_salt)
            
            # Prepare credentials JSON
            cred_json = json.dumps(credentials, sort_keys=True)
            cred_bytes = cred_json.encode('utf-8')
            
            # Generate random IV for GCM mode
            iv = os.urandom(16)  # 128-bit IV for GCM
            
            # Encrypt using AES-GCM
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Add authenticated data (empty in this case)
            encryptor.authenticate_additional_data(b"")
            
            # Encrypt the credentials
            ciphertext = encryptor.update(cred_bytes) + encryptor.finalize()
            
            # Get authentication tag
            auth_tag = encryptor.tag
            
            # Combine IV + ciphertext + auth_tag
            vault_data = iv + ciphertext + auth_tag
            
            # Write encrypted vault to file
            with open(self.vault_path, 'wb') as f:
                f.write(vault_data)
                
            print(f"{Fore.GREEN}🔐 AWS credentials encrypted to vault: {self.vault_path}{Style.RESET_ALL}")
            print(f"   📊 Vault size: {len(vault_data)} bytes")
            print(f"   🔑 Key derivation: PBKDF2-SHA256 ({self.config['vault_settings']['iterations']} iterations)")
            print(f"   🛡️  Device binding: {device_salt[:16]}...{device_salt[-4:]}")
            
            return True, "Credentials encrypted successfully"
            
        except Exception as e:
            return False, f"Encryption failed: {str(e)}"
            
    def decrypt_credentials(self, nfc_uid):
        """Decrypt AWS credentials from vault using NFC-derived key."""
        try:
            if not os.path.exists(self.vault_path):
                raise FileNotFoundError(f"Vault file not found: {self.vault_path}")
                
            # Generate device salt and derive key
            device_salt = self.generate_device_fingerprint()
            key = self.derive_vault_key(nfc_uid, device_salt)
            
            # Read encrypted vault
            with open(self.vault_path, 'rb') as f:
                vault_data = f.read()
                
            if len(vault_data) < 32:  # IV + minimum data + tag
                raise ValueError("Vault file appears corrupted or empty")
                
            # Extract components
            iv = vault_data[:16]           # 128-bit IV
            auth_tag = vault_data[-16:]    # 128-bit auth tag
            ciphertext = vault_data[16:-16] # Remaining ciphertext
            
            # Decrypt using AES-GCM
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Add authenticated data (empty)
            decryptor.authenticate_additional_data(b"")
            
            # Decrypt the credentials
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Parse JSON credentials
            credentials = json.loads(plaintext.decode('utf-8'))
            
            print(f"{Fore.GREEN}🔓 AWS vault decrypted successfully{Style.RESET_ALL}")
            print(f"   📊 Credentials loaded: {len(credentials)} fields")
            
            return True, credentials
            
        except Exception as e:
            return False, f"Decryption failed: {str(e)}"
            
    def create_sample_vault(self, nfc_uid):
        """Create a sample encrypted vault for testing."""
        sample_credentials = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "aws_region": "us-east-1",
            "role_arn": "arn:aws:iam::YOUR-ACCOUNT-ID:role/NFCAuthRole",
            "description": "Sample AWS credentials for NFC authentication testing"
        }
        
        success, message = self.encrypt_credentials(sample_credentials, nfc_uid)
        if success:
            print(f"{Fore.YELLOW}⚠️  Sample vault created with EXAMPLE credentials{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}   🔄 Replace with real AWS credentials before production use{Style.RESET_ALL}")
            
        return success, message
        
    def vault_info(self):
        """Display vault information."""
        if not os.path.exists(self.vault_path):
            print(f"{Fore.RED}❌ Vault file not found: {self.vault_path}{Style.RESET_ALL}")
            return False
            
        stat = os.stat(self.vault_path)
        print(f"\n{Fore.CYAN}📁 AWS Credential Vault Information{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*40}{Style.RESET_ALL}")
        print(f"   📄 File: {self.vault_path}")
        print(f"   📊 Size: {stat.st_size} bytes")
        print(f"   📅 Created: {stat.st_ctime}")
        print(f"   🔧 Modified: {stat.st_mtime}")
        print(f"   🔐 Encryption: AES-256-GCM")
        print(f"   🔑 Key Derivation: PBKDF2-SHA256 ({self.config['vault_settings']['iterations']} iterations)")
        print(f"   🛡️  Device Binding: Required")
        
        return True
        
    def delete_vault(self):
        """Securely delete vault file."""
        if not os.path.exists(self.vault_path):
            print(f"{Fore.YELLOW}⚠️  Vault file not found: {self.vault_path}{Style.RESET_ALL}")
            return False
            
        try:
            # Overwrite file with random data before deletion (basic secure delete)
            file_size = os.path.getsize(self.vault_path)
            with open(self.vault_path, 'wb') as f:
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
                
            # Delete the file
            os.remove(self.vault_path)
            print(f"{Fore.GREEN}🗑️  Vault securely deleted: {self.vault_path}{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to delete vault: {e}{Style.RESET_ALL}")
            return False

def main():
    """Main CLI interface for vault management."""
    import argparse
    
    parser = argparse.ArgumentParser(description="AWS NFC Credential Vault Manager")
    parser.add_argument("--create", action="store_true", help="Create new encrypted vault")
    parser.add_argument("--sample", action="store_true", help="Create sample vault with example credentials")
    parser.add_argument("--decrypt", action="store_true", help="Test vault decryption")
    parser.add_argument("--info", action="store_true", help="Display vault information")
    parser.add_argument("--delete", action="store_true", help="Delete vault file")
    parser.add_argument("--nfc-uid", default="04A2BC1122334455", help="NFC tag UID (for testing)")
    parser.add_argument("--vault", default="aws_vault_encrypted.bin", help="Vault file path")
    
    args = parser.parse_args()
    
    try:
        vault_manager = AWSVaultManager(vault_path=args.vault)
        
        if args.create:
            # Interactive credential entry
            print(f"\n{Fore.CYAN}🔐 Creating AWS Credential Vault{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}⚠️  Enter your AWS credentials (will be encrypted with NFC UID){Style.RESET_ALL}")
            
            credentials = {}
            credentials['aws_access_key_id'] = input("AWS Access Key ID: ").strip()
            credentials['aws_secret_access_key'] = input("AWS Secret Access Key: ").strip()
            credentials['aws_region'] = input("AWS Region [us-east-1]: ").strip() or "us-east-1"
            credentials['role_arn'] = input("Role ARN (optional): ").strip()
            
            if credentials['aws_access_key_id'] and credentials['aws_secret_access_key']:
                success, message = vault_manager.encrypt_credentials(credentials, args.nfc_uid)
                print(f"\n{Fore.GREEN if success else Fore.RED}{'✅' if success else '❌'} {message}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}❌ Missing required credentials{Style.RESET_ALL}")
                
        elif args.sample:
            success, message = vault_manager.create_sample_vault(args.nfc_uid)
            print(f"\n{Fore.GREEN if success else Fore.RED}{'✅' if success else '❌'} {message}{Style.RESET_ALL}")
            
        elif args.decrypt:
            success, result = vault_manager.decrypt_credentials(args.nfc_uid)
            if success:
                print(f"\n{Fore.GREEN}✅ Decryption successful{Style.RESET_ALL}")
                print(f"   🔑 Access Key ID: {result.get('aws_access_key_id', 'N/A')}")
                print(f"   🌍 Region: {result.get('aws_region', 'N/A')}")
                print(f"   🎭 Role ARN: {result.get('role_arn', 'None')}")
            else:
                print(f"\n{Fore.RED}❌ {result}{Style.RESET_ALL}")
                
        elif args.info:
            vault_manager.vault_info()
            
        elif args.delete:
            confirm = input(f"{Fore.YELLOW}⚠️  Delete vault '{args.vault}'? (y/N): {Style.RESET_ALL}")
            if confirm.lower() == 'y':
                vault_manager.delete_vault()
            else:
                print(f"{Fore.YELLOW}🚫 Vault deletion cancelled{Style.RESET_ALL}")
                
        else:
            print(f"\n{Fore.CYAN}AWS NFC Vault Manager{Style.RESET_ALL}")
            print(f"Use --help to see available options")
            print(f"\nExample usage:")
            print(f"  {Fore.GREEN}python3 aws_vault_manager.py --sample{Style.RESET_ALL}     # Create sample vault")
            print(f"  {Fore.GREEN}python3 aws_vault_manager.py --create{Style.RESET_ALL}     # Create real vault")
            print(f"  {Fore.GREEN}python3 aws_vault_manager.py --info{Style.RESET_ALL}       # Show vault info")
            print(f"  {Fore.GREEN}python3 aws_vault_manager.py --decrypt{Style.RESET_ALL}    # Test decryption")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Operation cancelled{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}💥 Fatal error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
