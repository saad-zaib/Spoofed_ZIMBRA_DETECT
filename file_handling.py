#!/usr/bin/env python3
import os
import logging
from email import policy
from email.parser import BytesParser

def find_email_files(base_path):
    """Recursively find all email message files in the Zimbra store directory."""
    print(f"Scanning directory: {base_path}")
    email_files = []
    for root, _, files in os.walk(base_path):
        for file in files:
            # Skip backup files
            if not file.endswith('.backup'):
                file_path = os.path.join(root, file)
                email_files.append(file_path)
    print(f"Found {len(email_files)} email files")
    return email_files

def extract_email_headers(email_path):
    """Extract headers from the email file."""
    try:
        with open(email_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
            print(f"Successfully parsed email: {email_path}")
            return msg
    except Exception as e:
        logging.error(f"Error reading {email_path}: {e}")
        print(f"ERROR: Failed to parse email: {email_path} - {e}")
        return None