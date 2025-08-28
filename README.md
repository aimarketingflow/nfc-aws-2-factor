# NFC AWS Authentication System - Public Version

This is a sanitized public version of the NFC AWS Authentication system that provides hardware-based AWS authentication using NFC tokens combined with EMF Chaos Engine technology.

## ⚠️ IMPORTANT SECURITY NOTICE

This public version contains **EXAMPLE CREDENTIALS ONLY**. All sensitive data has been replaced with generic placeholders:

- AWS Account ID: `YOUR-AWS-ACCOUNT-ID`
- Access Key ID: `AKIAIOSFODNN7EXAMPLE` 
- Secret Access Key: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`
- Role ARN: `arn:aws:iam::YOUR-AWS-ACCOUNT-ID:role/NFCAuthRole`

**You must replace these with your actual AWS credentials before use.**

## 🔐 System Overview

The NFC AWS Authentication system provides:

- **Hardware-based authentication** using physical NFC tokens
- **Combined NFC + Chaos Engine** encryption for enhanced security
- **Device fingerprinting** for binding credentials to specific machines
- **Rate limiting** and security controls
- **Encrypted credential vaults** using AES-256-GCM encryption
- **AWS STS token issuance** with configurable session durations

## 📁 File Structure

```
NFC_AWS_PUBLIC/
├── README.md                    # This file
├── aws_config.json             # Configuration settings
├── nfc-aws_credentials.csv     # Sample AWS console credentials
├── rootkey.csv                 # Sample AWS API credentials
├── aws_nfc_authenticator.py    # Main authentication client
├── aws_combined_vault.py       # NFC + Chaos vault manager
├── aws_vault_manager.py        # Credential encryption/decryption
└── aws_sts_server.py           # STS authentication server
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip3 install boto3 cryptography colorama flask psutil
```

### 2. Configure AWS Credentials

Edit the credential files with your actual AWS information:

**aws_config.json:**
```json
{
    "aws_region": "us-east-1",
    "role_arn": "arn:aws:iam::YOUR-ACTUAL-ACCOUNT-ID:role/NFCAuthRole"
}
```

**rootkey.csv:**
```csv
Access key ID,Secret access key
YOUR-ACTUAL-ACCESS-KEY,YOUR-ACTUAL-SECRET-KEY
```

### 3. Create Encrypted Vault

```bash
# Create sample vault for testing
python3 aws_vault_manager.py --sample

# Or create vault with your credentials
python3 aws_vault_manager.py --create
```

### 4. Start Authentication Server

```bash
python3 aws_sts_server.py
```

### 5. Test Authentication

```bash
python3 aws_nfc_authenticator.py --test
```

## 🔧 Configuration Options

### Session Duration
- Minimum: 15 minutes (900 seconds)
- Maximum: 12 hours (43200 seconds)
- Default: 15 minutes

### Security Settings
- **Rate limiting**: 10 attempts per hour per device
- **Device fingerprinting**: Required for credential binding
- **IP binding**: Optional (disabled by default)
- **Encryption**: AES-256-GCM with PBKDF2-SHA256 key derivation

## 🛡️ Security Features

### Multi-Factor Authentication
1. **Physical NFC token** - Something you have
2. **Chaos Engine integration** - Environmental RF entropy
3. **Device binding** - Machine-specific fingerprinting

### Encryption
- **AES-256-GCM** for credential vault encryption
- **PBKDF2-SHA256** with 100,000 iterations for key derivation
- **Device-specific salts** for additional security

### Rate Limiting
- Failed authentication attempts are tracked per device
- Automatic lockout after exceeding attempt limits
- Configurable lockout duration and attempt thresholds

## 📋 Usage Examples

### Create Vault
```bash
python3 aws_vault_manager.py --create
```

### Test Vault Decryption
```bash
python3 aws_vault_manager.py --decrypt --nfc-uid "YOUR-NFC-UID"
```

### Run Authentication with Custom Duration
```bash
python3 aws_nfc_authenticator.py --test --duration 60  # 60 minutes
```

### Check Vault Information
```bash
python3 aws_vault_manager.py --info
```

## 🔗 API Endpoints

When running the STS server, the following endpoints are available:

- `POST /auth/aws-token` - Request AWS STS token
- `GET /health` - Health check
- `GET /status` - Server status and configuration

## ⚠️ Production Deployment

Before deploying to production:

1. **Replace all example credentials** with real AWS credentials
2. **Configure proper IAM roles** and policies
3. **Enable IP binding** if required for your environment
4. **Set up proper logging** and monitoring
5. **Use HTTPS** for all communications
6. **Implement proper secret management** (AWS Secrets Manager, etc.)

## 🔍 Troubleshooting

### Common Issues

**Vault decryption fails:**
- Ensure NFC UID is correct
- Check device fingerprint consistency
- Verify vault file exists and isn't corrupted

**STS token request fails:**
- Verify AWS credentials are valid
- Check IAM role permissions
- Ensure role trust policy allows assumption

**Rate limiting triggered:**
- Wait for lockout period to expire
- Check device fingerprint generation
- Review authentication logs

## 📚 Dependencies

- `boto3` - AWS SDK for Python
- `cryptography` - Encryption and key derivation
- `colorama` - Cross-platform colored terminal output
- `flask` - Web server for STS authentication
- `psutil` - System information for device fingerprinting

## 🤝 Contributing

This is a public sanitized version. For the full implementation with advanced features, see the private repository.

## 📄 License

Open source - see LICENSE file for details.

## 🚨 Security Disclaimer

This system requires physical NFC hardware for proper security. The public version is for educational and testing purposes. Always use proper security practices in production environments.
