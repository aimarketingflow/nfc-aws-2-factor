#!/usr/bin/env python3
"""
AWS STS Authentication Server - AIMF Auth Server for AWS
Adapted from proven NFC Google Cloud Authentication patterns

Handles NFC-authenticated AWS STS token issuance with device binding.
"""

import os
import json
import time
import hashlib
import hmac
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from colorama import init, Fore, Style

# Initialize colorama for colored output
init()

app = Flask(__name__)

class AWSSTSServer:
    def __init__(self, config_path="aws_config.json"):
        """Initialize AWS STS Authentication Server."""
        self.config = self.load_config(config_path)
        self.failed_attempts = {}  # Track failed attempts per device
        
    def load_config(self, config_path):
        """Load AWS configuration settings."""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"{Fore.RED}❌ Config file not found: {config_path}{Style.RESET_ALL}")
            raise
            
    def validate_device_fingerprint(self, request_fingerprint, stored_fingerprint=None):
        """Validate device fingerprint for binding."""
        # In production, store and validate against registered devices
        # For now, accept any non-empty fingerprint
        return bool(request_fingerprint and len(request_fingerprint) > 20)
        
    def check_rate_limits(self, device_fingerprint):
        """Check rate limiting for device."""
        current_time = time.time()
        window_start = current_time - 3600  # 1 hour window
        
        if device_fingerprint in self.failed_attempts:
            # Clean old attempts
            self.failed_attempts[device_fingerprint] = [
                attempt_time for attempt_time in self.failed_attempts[device_fingerprint]
                if attempt_time > window_start
            ]
            
            # Check if over limit
            if len(self.failed_attempts[device_fingerprint]) >= self.config['security']['max_attempts_per_hour']:
                return False, "Rate limit exceeded"
                
        return True, "OK"
        
    def record_failed_attempt(self, device_fingerprint):
        """Record failed authentication attempt."""
        if device_fingerprint not in self.failed_attempts:
            self.failed_attempts[device_fingerprint] = []
        self.failed_attempts[device_fingerprint].append(time.time())
        
    def assume_role_with_credentials(self, aws_access_key_id, aws_secret_access_key, 
                                   role_arn, session_name, duration_seconds):
        """Assume AWS role using provided credentials."""
        try:
            # Create STS client with provided credentials
            sts_client = boto3.client(
                'sts',
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=self.config.get('aws_region', 'us-east-1')
            )
            
            # Assume the specified role
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=duration_seconds,
                Tags=[
                    {
                        'Key': 'nfc:present',
                        'Value': 'true'
                    },
                    {
                        'Key': 'auth:method',
                        'Value': 'nfc-hardware'
                    },
                    {
                        'Key': 'session:created',
                        'Value': str(int(time.time()))
                    }
                ]
            )
            
            return response['Credentials'], None
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            return None, f"STS Error ({error_code}): {error_message}"
        except NoCredentialsError:
            return None, "Invalid AWS credentials provided"
        except Exception as e:
            return None, f"Unexpected error: {str(e)}"

# Create global server instance
sts_server = AWSSTSServer()

@app.route('/auth/aws-token', methods=['POST'])
def aws_token():
    """Handle AWS STS token requests."""
    try:
        # Validate request
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
            
        data = request.get_json()
        
        # Required fields
        required_fields = ['aws_access_key_id', 'aws_secret_access_key', 
                          'role_arn', 'device_fingerprint']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
                
        # Extract request data
        aws_access_key_id = data['aws_access_key_id']
        aws_secret_access_key = data['aws_secret_access_key']
        role_arn = data['role_arn']
        device_fingerprint = data['device_fingerprint']
        session_name = data.get('session_name', 'nfc-auth-session')
        duration = data.get('duration', 900)  # 15 minutes default
        
        # Security validations
        
        # 1. Rate limiting
        rate_ok, rate_message = sts_server.check_rate_limits(device_fingerprint)
        if not rate_ok:
            sts_server.record_failed_attempt(device_fingerprint)
            return jsonify({
                "error": "RATE_LIMIT_EXCEEDED",
                "message": rate_message,
                "retry_after": 3600
            }), 429
            
        # 2. Device fingerprint validation
        if not sts_server.validate_device_fingerprint(device_fingerprint):
            sts_server.record_failed_attempt(device_fingerprint)
            return jsonify({
                "error": "INVALID_DEVICE",
                "message": "Device fingerprint validation failed"
            }), 401
            
        # 3. Optional IP binding (if enabled in config)
        if sts_server.config['security'].get('ip_binding_enabled', False):
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            # In production, validate against stored allowed IPs
            print(f"{Fore.YELLOW}🌐 Client IP: {client_ip}{Style.RESET_ALL}")
            
        # Attempt to assume role
        print(f"{Fore.YELLOW}🛡️  Processing AWS STS token request...{Style.RESET_ALL}")
        
        credentials, error = sts_server.assume_role_with_credentials(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            role_arn=role_arn,
            session_name=session_name,
            duration_seconds=duration
        )
        
        if error:
            sts_server.record_failed_attempt(device_fingerprint)
            print(f"{Fore.RED}❌ STS token request failed: {error}{Style.RESET_ALL}")
            return jsonify({
                "error": "STS_ASSUMPTION_FAILED",
                "message": error
            }), 401
            
        # Success - return temporary credentials
        print(f"{Fore.GREEN}✅ STS token issued successfully{Style.RESET_ALL}")
        
        response_data = {
            "AccessKeyId": credentials['AccessKeyId'],
            "SecretAccessKey": credentials['SecretAccessKey'],
            "SessionToken": credentials['SessionToken'],
            "Expiration": credentials['Expiration'].isoformat(),
            "message": "AWS STS token issued successfully",
            "expires_in_seconds": duration
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"{Fore.RED}💥 Server error: {str(e)}{Style.RESET_ALL}")
        return jsonify({
            "error": "INTERNAL_SERVER_ERROR",
            "message": "Authentication server error"
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "AWS STS Authentication Server",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }), 200

@app.route('/status', methods=['GET'])
def server_status():
    """Server status endpoint."""
    return jsonify({
        "service": "AIMF AWS STS Server",
        "config": {
            "aws_region": sts_server.config.get('aws_region'),
            "session_duration_max": sts_server.config.get('session_duration_seconds'),
            "rate_limit_per_hour": sts_server.config['security']['max_attempts_per_hour'],
            "device_binding": sts_server.config['security']['device_fingerprint_required'],
            "ip_binding": sts_server.config['security']['ip_binding_enabled']
        },
        "active_rate_limits": len(sts_server.failed_attempts),
        "uptime": time.time()
    }), 200

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405

def main():
    """Main server entry point."""
    print(f"\n{Fore.CYAN}🛡️  AIMF AWS STS Authentication Server{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    
    # Load and display config
    config = sts_server.config
    auth_server = config['auth_server']
    
    print(f"{Fore.GREEN}✅ Server configuration loaded{Style.RESET_ALL}")
    print(f"   🌐 Host: {auth_server['host']}")
    print(f"   🔌 Port: {auth_server['port']}")
    print(f"   🌍 AWS Region: {config.get('aws_region', 'us-east-1')}")
    print(f"   ⏱️  Session Duration: {config.get('session_duration_seconds', 900)}s")
    print(f"   🔒 Rate Limit: {config['security']['max_attempts_per_hour']}/hour")
    
    print(f"\n{Fore.YELLOW}🚀 Starting server...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}📋 Endpoints:{Style.RESET_ALL}")
    print(f"   POST /auth/aws-token  - AWS STS token issuance")
    print(f"   GET  /health          - Health check")
    print(f"   GET  /status          - Server status")
    
    try:
        # Start Flask development server
        app.run(
            host=auth_server['host'],
            port=auth_server['port'],
            debug=False,  # Set to True for development
            threaded=True
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Server shutdown requested{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}💥 Server startup failed: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
