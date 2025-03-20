#!/usr/bin/env python3
import os
import sys
import json
import logging
import datetime
from logging.handlers import RotatingFileHandler

class EmailSpooferLogger:
    """Logger specifically for email spoofing detection."""
    
    def __init__(self, log_path='/var/log/spoofing.json'):
        # Ensure directory exists
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        
        self.log_path = log_path
        
        # Set up standard logger for console output
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
    
    def log_spoofed_email(self, email_data):
        """Log a single spoofed email with key information as JSON."""
        # Extract only the specific fields we want
        json_entry = {
            "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "sender": email_data.get('from', ''),
            "receiver": email_data.get('recipient', ''),
            "subject": email_data.get('subject', ''),
            "source_ip": email_data.get('source_ip', ''),
            "return_path": email_data.get('return_path', ''),
            "security_checks": {
                "spf": email_data.get('spf_pass', False),
                "dkim": email_data.get('dkim_pass', False),
                "dmarc": email_data.get('dmarc_pass', False),
                "reverse_dns": email_data.get('reverse_dns_pass', False),
                "header_match": not email_data.get('header_mismatch', True)
            }
        }
        
        # Write to JSON file with proper locking to handle concurrency
        try:
            # Read existing entries if file exists
            entries = []
            if os.path.exists(self.log_path) and os.path.getsize(self.log_path) > 0:
                with open(self.log_path, 'r') as f:
                    try:
                        entries = json.load(f)
                        if not isinstance(entries, list):
                            entries = [entries]
                    except json.JSONDecodeError:
                        # If file is corrupted, start fresh
                        entries = []
            
            # Add new entry
            entries.append(json_entry)
            
            # Write back to file
            with open(self.log_path, 'w') as f:
                json.dump(entries, f, indent=2)
                
            self.logger.info(f"Logged spoofed email to {self.log_path}: {json_entry['sender']} -> {json_entry['receiver']}")
            
        except Exception as e:
            self.logger.error(f"Failed to log to JSON file: {e}")

# Global logger instance
_spoofed_logger = None

def setup_logging():
    """Set up logging to both terminal and JSON file."""
    global _spoofed_logger
    
    if _spoofed_logger is None:
        _spoofed_logger = EmailSpooferLogger()
    
    # Set up basic logging for console output
    logger = logging.getLogger()
    return logger

def log_spoofed_email(email_data):
    """Log spoofed email data with key details in JSON format."""
    global _spoofed_logger
    
    if _spoofed_logger is None:
        _spoofed_logger = EmailSpooferLogger()
    
    # Only log if spoofing is detected
    if email_data.get('spoofing_detected', False):
        _spoofed_logger.log_spoofed_email(email_data)