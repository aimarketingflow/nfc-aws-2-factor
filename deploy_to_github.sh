#!/bin/bash

echo "🚀 Deploying NFC AWS Authentication to GitHub..."
echo "================================================"

# Initialize git repository
echo "📁 Initializing git repository..."
git init
echo "✅ Git repository initialized"

# Add remote origin
echo "🔗 Adding remote origin..."
git remote add origin https://github.com/aimarketingflow/nfc-aws-2-factor.git
echo "✅ Remote origin added"

# Check git status
echo "📋 Checking git status..."
git status

# Add all files
echo "📦 Adding all files..."
git add .
echo "✅ All files staged"

# Commit with message
echo "💾 Committing files..."
git commit -m "Initial release: NFC AWS Authentication System

- Hardware-based AWS authentication using NFC tokens
- Combined NFC + Chaos Engine encryption
- AES-256-GCM encrypted credential vaults
- Device fingerprinting and rate limiting
- AWS STS token issuance with configurable sessions
- Sanitized public version with example credentials

Ready for community testing with physical NFC hardware."
echo "✅ Files committed"

# Push to GitHub
echo "🌐 Pushing to GitHub..."
git push -u origin main
echo "✅ Successfully pushed to GitHub!"

echo ""
echo "🎉 Deployment complete!"
echo "Repository: https://github.com/aimarketingflow/nfc-aws-2-factor"
