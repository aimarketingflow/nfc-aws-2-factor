#!/usr/bin/env python3
"""
AWS Combined Vault - Uses NFC + Chaos Engine key for encryption
"""

import os
import json
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from colorama import init, Fore, Style
from nfc_chaos_scanner import NFCChaosScanner

init()

class AWSCombinedVault:
    def __init__(self):
        """Initialize AWS Combined Vault."""
        self.vault_file = "aws_combined_vault.bin"
        self.scanner = NFCChaosScanner()
        
    def create_vault_with_combined_key(self):
        """Create AWS vault with combined NFC + chaos key."""
        try:
            print(f"{Fore.CYAN}🔐 Creating AWS vault with combined NFC + chaos key{Style.RESET_ALL}\n")
            
            # Perform combined NFC + chaos scan (creation mode)
            nfc_uid, chaos_value = self.scanner.scan_nfc_with_chaos(is_creation=True)
            if not nfc_uid or not chaos_value:
                print(f"{Fore.RED}❌ NFC + chaos scan failed{Style.RESET_ALL}")
                return False
                
            # Derive vault encryption key
            vault_key = self.scanner.create_combined_vault_key(nfc_uid, chaos_value)
            
            # AWS credentials to encrypt (REPLACE WITH YOUR ACTUAL CREDENTIALS)
            credentials = {
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "aws_region": "us-east-1",
                "role_arn": "arn:aws:iam::YOUR-AWS-ACCOUNT-ID:role/NFCAuthRole"
            }
            
            # Encrypt credentials
            cred_json = json.dumps(credentials, sort_keys=True)
            cred_bytes = cred_json.encode('utf-8')
            
            # AES-GCM encryption
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(vault_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encryptor.authenticate_additional_data(b"")
            
            ciphertext = encryptor.update(cred_bytes) + encryptor.finalize()
            auth_tag = encryptor.tag
            
            # Save encrypted vault
            vault_data = iv + ciphertext + auth_tag
            with open(self.vault_file, 'wb') as f:
                f.write(vault_data)
                
            print(f"{Fore.GREEN}🔐 Vault encryption key derived{Style.RESET_ALL}")
            print(f"{Fore.GREEN}🔐 AWS vault created with combined key{Style.RESET_ALL}")
            print(f"   {Fore.CYAN}📊 Vault size: {len(vault_data)} bytes{Style.RESET_ALL}")
            print(f"   {Fore.CYAN}🏷️  NFC authentication successful{Style.RESET_ALL}")
            print(f"   {Fore.YELLOW}📡 Chaos key established{Style.RESET_ALL}")
            
            print(f"\n{Fore.GREEN}✅ Vault created successfully{Style.RESET_ALL}")
            return True, "Vault created successfully"
            
        except Exception as e:
            return False, f"Vault creation failed: {str(e)}"
            
    def unlock_vault_with_combined_key(self):
        """Unlock AWS vault using combined NFC + chaos key."""
        try:
            if not os.path.exists(self.vault_file):
                return False, "Vault file not found"
                
            print(f"{Fore.CYAN}🔓 Unlocking AWS vault with combined key{Style.RESET_ALL}")
            
            # Perform combined scan
            nfc_uid, chaos_value = self.scanner.scan_nfc_with_chaos()
            
            if not nfc_uid or not chaos_value:
                return False, "NFC + chaos scan failed"
                
            # Recreate vault key
            vault_key = self.scanner.create_combined_vault_key(nfc_uid, chaos_value)
            
            # Read encrypted vault
            with open(self.vault_file, 'rb') as f:
                vault_data = f.read()
                
            # Decrypt vault
            iv = vault_data[:16]
            auth_tag = vault_data[-16:]
            ciphertext = vault_data[16:-16]
            
            cipher = Cipher(algorithms.AES(vault_key), modes.GCM(iv, auth_tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(b"")
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            credentials = json.loads(plaintext.decode('utf-8'))
            
            print(f"{Fore.GREEN}🔓 AWS vault unlocked successfully{Style.RESET_ALL}")
            print(f"   🔑 Access Key: {credentials['aws_access_key_id']}")
            print(f"   🌍 Region: {credentials['aws_region']}")
            
            return True, credentials
            
        except Exception as e:
            return False, f"Vault unlock failed: {str(e)}"

def main():
    """Main CLI interface."""
    import argparse
    
    parser = argparse.ArgumentParser(description="AWS Combined Vault - NFC + Chaos")
    parser.add_argument("--create", action="store_true", help="Create vault with combined key")
    parser.add_argument("--unlock", action="store_true", help="Unlock vault with combined key")
    
    args = parser.parse_args()
    
    vault = AWSCombinedVault()
    
    if args.create:
        success, message = vault.create_vault_with_combined_key()
        print(f"\n{Fore.GREEN if success else Fore.RED}{'✅' if success else '❌'} {message}{Style.RESET_ALL}")
        
    elif args.unlock:
        success, result = vault.unlock_vault_with_combined_key()
        if success:
            print(f"\n{Fore.GREEN}✅ Vault unlocked - credentials ready for AWS authentication{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}❌ {result}{Style.RESET_ALL}")
            
    else:
        print(f"\n{Fore.CYAN}AWS Combined Vault - NFC + Chaos Engine{Style.RESET_ALL}")
        print(f"--create  Create vault with combined NFC + chaos key")
        print(f"--unlock  Unlock vault with combined NFC + chaos key")

if __name__ == "__main__":
    main()
