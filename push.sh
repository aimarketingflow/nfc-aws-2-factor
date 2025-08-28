#!/bin/bash
set -e

echo "Initializing git..."
git init

echo "Adding remote..."
git remote add origin https://github.com/aimarketingflow/nfc-aws-2-factor.git

echo "Adding files..."
git add .

echo "Committing..."
git commit -m "Initial release: NFC AWS Authentication System"

echo "Pushing..."
git push -u origin main

echo "Done!"
