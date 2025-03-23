#!/usr/bin/env python3
import os
import re
import time
import email
import hashlib
import base64
import logging
import requests
import subprocess
import email.utils
from pathlib import Path
from typing import Set, Dict, Any

# Configuration
ZIMBRA_PATH = "/opt/zimbra/store"
MALWARE_BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
MALICIOUS_TAG = "MALICIOUS"

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
attachment_logger = logging.getLogger('attachment_log')
malicious_logger = logging.getLogger('malicious_log')
zimbra_logger = logging.getLogger('zimbra_log')

attachment_handler = logging.FileHandler('attachment_found.log')
malicious_handler = logging.FileHandler('malicious_attachment.log')
zimbra_handler = logging.FileHandler('zimbra_operations.log')

attachment_logger.addHandler(attachment_handler)
malicious_logger.addHandler(malicious_handler)
zimbra_logger.addHandler(zimbra_handler)

# Keep track of processed emails to avoid reprocessing
processed_emails = {}

def calculate_file_hash(file_data: bytes) -> str:
    """Calculate SHA256 hash of file data."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_data)
    return sha256_hash.hexdigest()

def check_hash_malicious(file_hash: str) -> bool:
    """Check if the hash is malicious using MalwareBazaar."""
    try:
        response = requests.post(MALWARE_BAZAAR_API, data={'query': 'get_info', 'hash': file_hash})
        if response.status_code == 200:
            data = response.json()
            return 'data' in data  # Malicious if data exists
    except Exception as e:
        logging.error(f"Error checking hash {file_hash}: {str(e)}")
    return False  # Not malicious

def extract_recipient_from_path(path):
    """Extract recipient email from the Zimbra path structure."""
    # Default mailbox for testing
    default_mailbox = "saad@mail.cybersilo.in"

    # Try to extract additional information from path
    try:
        # For more accurate mailbox extraction in production,
        # you might want to create a mapping from Zimbra store paths
        # to actual email addresses
        pass
    except Exception as e:
        logging.warning(f"Could not extract account info from path: {e}")

    # Return the default mailbox
    return default_mailbox

def extract_email_info(email_path, msg):
    """Extract information needed to tag the email in Zimbra, including precise date/time."""
    try:
        # Extract recipient from the message
        mailbox = None
        to_header = msg.get('To', '')

        # Extract email address from To header
        to_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)', to_header)
        if to_match:
            mailbox = to_match.group(1)
            print(f"Extracted recipient from To header: {mailbox}")

        # If recipient not found in headers, try to extract from path
        if not mailbox:
            mailbox = extract_recipient_from_path(email_path)
            print(f"Extracted recipient from path: {mailbox}")

        # Get from address and subject for searching
        from_header = msg.get('From', '')
        subject = msg.get('Subject', '')

        # Get date for more precise searching - extract both header date and also file creation time
        date_header = msg.get('Date', '')
        # Get the file modification time as a backup timestamp
        file_timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(email_path)))

        # Parse the date header to a standardized format if possible
        parsed_date = None
        try:
            if date_header:
                # Try to parse the email date header into a datetime object
                parsed_date = email.utils.parsedate_to_datetime(date_header)
                if parsed_date:
                    # Format to a consistent format that works with Zimbra search
                    date_header = parsed_date.strftime("%m/%d/%y %H:%M")
        except Exception as e:
            logging.warning(f"Could not parse date header: {e}")
            date_header = None

        return {
            'mailbox': mailbox,
            'from': from_header,
            'subject': subject,
            'date_header': date_header,
            'file_timestamp': file_timestamp,
            'message_id': msg.get('Message-ID', '')
        }
    except Exception as e:
        logging.error(f"Error extracting email info from {email_path}: {e}")
        print(f"Error extracting email info: {e}")
        return None

def run_zimbra_command(command):
    """Run a Zimbra command and return the output."""
    try:
        print(f"Executing: {command}")
        zimbra_logger.info(f"Executing: {command}")
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        stdout = stdout.decode('utf-8')
        stderr = stderr.decode('utf-8')

        if process.returncode != 0:
            print(f"Command failed with return code {process.returncode}")
            print(f"Error: {stderr}")
            zimbra_logger.error(f"Command failed: {stderr}")
            return None

        print(f"Command output: {stdout}")
        zimbra_logger.info(f"Command successful")
        return stdout
    except Exception as e:
        print(f"Exception executing command: {e}")
        zimbra_logger.error(f"Exception executing command: {e}")
        return None

def extract_all_message_ids(output):
    """Extract all message IDs from search results."""
    if not output:
        return []

    message_ids = []
    lines = output.strip().split('\n')
    content_lines = [line for line in lines if line.strip() and not line.startswith('num:') and not '--' in line]

    # Remove header rows
    for i, line in enumerate(content_lines):
        if "Id  Type" in line:
            content_lines = content_lines[i+1:]
            break

    for line in content_lines:
        match = re.search(r'^\s*\d+\.\s+(\d+)', line)
        if match:
            message_ids.append(match.group(1))

    return message_ids

def search_specific_email(mailbox, email_info):
    """Search for a specific email using Zimbra-compatible search criteria."""
    # Start with a base search using the most reliable criteria
    base_criteria = []

    if email_info.get('from'):
        # Clean up the from address for the search query
        clean_from = email_info['from'].replace('<', '').replace('>', '')
        clean_from = clean_from.replace('"', '\\"')
        base_criteria.append(f'from:"{clean_from}"')

    if email_info.get('subject'):
        # Escape special characters in subject
        clean_subject = email_info['subject'].replace('"', '\\"')
        base_criteria.append(f'subject:"{clean_subject}"')

    # Add date criteria - format MM/DD/YY
    date_criteria = None
    if email_info.get('date_header'):
        # Extract just the date part
        date_parts = email_info['date_header'].split()
        if date_parts:
            date_criteria = date_parts[0]

    if not date_criteria and email_info.get('file_timestamp'):
        # Try to get date from file timestamp
        date_parts = email_info['file_timestamp'].split()
        if date_parts and len(date_parts) > 0:
            # Convert YYYY-MM-DD to MM/DD/YY
            try:
                year, month, day = date_parts[0].split('-')
                date_criteria = f"{month}/{day}/{year[2:]}"
            except:
                pass

    if date_criteria:
        base_criteria.append(f'date:{date_criteria}')
    else:
        # If no date criteria could be determined, use a recent timeframe
        base_criteria.append('after:-1day')

    # Use a two-stage approach:
    # 1. First search with base criteria (from, subject, date)
    base_query = " ".join(base_criteria)
    command = f'su - zimbra -c "zmmailbox -z -m {mailbox} s -t message \'{base_query}\'"'

    print(f"Searching with criteria: {base_query}")
    output = run_zimbra_command(command)

    # Extract message IDs from the search results
    message_ids = extract_all_message_ids(output) if output else []

    # If we found exactly one message, return it
    if len(message_ids) == 1:
        return message_ids[0]

    # If we found multiple messages, try to refine the search
    if len(message_ids) > 1:
        # Try to extract the time from the headers
        email_time = None

        # Extract from date_header
        if email_info.get('date_header'):
            time_parts = email_info['date_header'].split()
            if len(time_parts) > 1:
                email_time = time_parts[1]

        # Or extract from file_timestamp
        if not email_time and email_info.get('file_timestamp'):
            time_parts = email_info['file_timestamp'].split()
            if len(time_parts) > 1:
                email_time = time_parts[1]

        # If we have a time, try to match it with the search results
        if email_time:
            print(f"Trying to match emails with time: {email_time}")
            # We'll need to get the full details of each message to compare times
            for msg_id in message_ids:
                # Get message details
                get_command = f'su - zimbra -c "zmmailbox -z -m {mailbox} gm {msg_id}"'
                msg_details = run_zimbra_command(get_command)

                if msg_details and email_time in msg_details:
                    print(f"Found message with matching time: {msg_id}")
                    return msg_id

        # If we couldn't match by time, try message-id
        if email_info.get('message_id') and email_info['message_id'].strip():
            clean_msgid = email_info['message_id'].replace('<', '').replace('>', '')
            for msg_id in message_ids:
                # Get message details and look for matching message ID
                get_command = f'su - zimbra -c "zmmailbox -z -m {mailbox} gm {msg_id}"'
                msg_details = run_zimbra_command(get_command)

                if msg_details and clean_msgid in msg_details:
                    print(f"Found message with matching Message-ID: {msg_id}")
                    return msg_id

        # If we still can't determine which message, use the most recent one
        print(f"Unable to narrow down messages, using most recent of {len(message_ids)} messages")
        return message_ids[0]

    # If we couldn't find any messages, return None
    print("No matching messages found")
    return None

def check_tag_exists(mailbox, tag):
    """Check if the tag exists for the mailbox."""
    command = f"su - zimbra -c \"zmmailbox -z -m {mailbox} gat\""
    output = run_zimbra_command(command)

    if output is None:
        return False

    return tag in output

def create_tag(mailbox, tag):
    """Create a tag for the mailbox if it doesn't exist."""
    if not check_tag_exists(mailbox, tag):
        print(f"Creating tag {tag} for mailbox {mailbox}")
        command = f"su - zimbra -c \"zmmailbox -z -m {mailbox} ct {tag}\""
        return run_zimbra_command(command) is not None
    else:
        print(f"Tag {tag} already exists for mailbox {mailbox}")
        return True

def check_if_email_already_tagged(mailbox, message_id, tag):
    """Check if a specific email is already tagged with the tag."""
    command = f"su - zimbra -c \"zmmailbox -z -m {mailbox} gm {message_id}\""
    output = run_zimbra_command(command)

    if not output:
        return False

    # Check if the tag appears in the message details
    tag_pattern = f"t=\"{tag}\"|Tag: {tag}"
    return bool(re.search(tag_pattern, output))

def add_tag_to_email(mailbox, message_id, tag):
    """Add the email to the tag if not already tagged."""
    # First check if the email is already tagged
    if check_if_email_already_tagged(mailbox, message_id, tag):
        print(f"Message {message_id} is already tagged with {tag}, skipping")
        return True

    print(f"Adding message {message_id} to tag {tag} for mailbox {mailbox}")
    command = f"su - zimbra -c \"zmmailbox -z -m {mailbox} tm {message_id} {tag}\""
    return run_zimbra_command(command) is not None

def process_email_file(file_path: Path) -> Dict[str, Any]:
    """Process a single email file, check for attachments, and return email info."""
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
            msg = email.message_from_bytes(file_data)

        # Extract email info for tagging
        email_info = extract_email_info(str(file_path), msg)

        malicious_attachments = []

        # Check for attachments
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue

            filename = part.get_filename()
            is_attachment = filename or (part.get('Content-Disposition') and 'attachment' in part.get('Content-Disposition'))

            if is_attachment:
                if part.get('Content-Transfer-Encoding') == 'base64':
                    attachment_data = base64.b64decode(part.get_payload())
                else:
                    attachment_data = part.get_payload(decode=True)

                file_hash = calculate_file_hash(attachment_data)
                log_entry = f"Filename: {filename}, Hash: {file_hash}, Path: {file_path}"
                attachment_logger.info(log_entry)

                if check_hash_malicious(file_hash):
                    malicious_entry = f"[MALICIOUS] {filename} - Hash: {file_hash} - Email: {file_path}"
                    malicious_logger.info(malicious_entry)
                    print(malicious_entry)
                    malicious_attachments.append({
                        'filename': filename,
                        'hash': file_hash
                    })
                else:
                    print(f"[CLEAN] {filename} - Hash: {file_hash}")

        if email_info:
            email_info['malicious_attachments'] = malicious_attachments
            email_info['has_malicious_content'] = len(malicious_attachments) > 0

        return email_info

    except Exception as e:
        logging.error(f"Error processing {file_path}: {str(e)}")
        return None

def scan_directory(processed_files: Set[str]) -> Set[str]:
    """Scan directory and return set of new files."""
    current_files = set()
    for root, _, files in os.walk(ZIMBRA_PATH):
        for file in files:
            if file.endswith('.msg'):
                file_path = str(Path(root) / file)
                current_files.add(file_path)
    return current_files - processed_files

def tag_email_with_malicious_content(email_info):
    """Tag an email as malicious in Zimbra."""
    if not email_info or not email_info.get('has_malicious_content'):
        return False

    mailbox = email_info.get('mailbox')
    if not mailbox:
        print("No mailbox information available for tagging")
        return False

    # Create the MALICIOUS tag if it doesn't exist
    if not create_tag(mailbox, MALICIOUS_TAG):
        print(f"Failed to create {MALICIOUS_TAG} tag for {mailbox}")
        return False

    # Search for the email in Zimbra
    message_id = search_specific_email(mailbox, email_info)
    if not message_id:
        print(f"Could not find email in Zimbra for {mailbox}")
        return False

    # Add the tag to the email
    if add_tag_to_email(mailbox, message_id, MALICIOUS_TAG):
        print(f"Successfully tagged email with {MALICIOUS_TAG} tag in Zimbra")

        # Log detailed information about the malicious content
        malicious_attachments = email_info.get('malicious_attachments', [])
        for attachment in malicious_attachments:
            malicious_logger.info(f"Tagged message with ID {message_id} - Malicious attachment: {attachment['filename']} - Hash: {attachment['hash']}")

        return True
    else:
        print(f"Failed to tag email with {MALICIOUS_TAG} tag in Zimbra")
        return False

def cleanup_processed_emails(processed_emails, max_age=86400):
    """Remove old entries from the processed emails dictionary to prevent memory bloat."""
    current_time = time.time()
    keys_to_remove = []

    for key, info in processed_emails.items():
        timestamp = info.get('processed_timestamp') or info.get('tagged_timestamp')
        if timestamp and (current_time - timestamp) > max_age:
            keys_to_remove.append(key)

    for key in keys_to_remove:
        del processed_emails[key]

    if keys_to_remove:
        print(f"Cleaned up {len(keys_to_remove)} old entries from processed emails cache")

def monitor_directory():
    """Continuously monitor directory for new files and process them."""
    print(f"Monitoring {ZIMBRA_PATH} for new emails...")
    processed_files = set()

    try:
        while True:
            # Scan for new email files
            new_files = scan_directory(processed_files)

            for file_path in new_files:
                path_obj = Path(file_path)
                print(f"Processing new email: {path_obj}")

                # Process the email to check for malicious attachments
                email_info = process_email_file(path_obj)

                # If the email has malicious content, tag it in Zimbra
                if email_info and email_info.get('has_malicious_content'):
                    tag_email_with_malicious_content(email_info)

                    # Store information about the processed email
                    processed_emails[file_path] = {
                        'processed_timestamp': time.time(),
                        'tagged_timestamp': time.time(),
                        'mailbox': email_info.get('mailbox'),
                        'subject': email_info.get('subject'),
                        'has_malicious_content': True
                    }
                else:
                    processed_emails[file_path] = {
                        'processed_timestamp': time.time(),
                        'has_malicious_content': False
                    }

                # Add to processed files set
                processed_files.add(file_path)

            # Clean up old entries periodically
            if len(processed_emails) > 1000:  # Arbitrary threshold
                cleanup_processed_emails(processed_emails)

            # Sleep to avoid excessive CPU usage
            time.sleep(1)

    except KeyboardInterrupt:
        print("Monitoring stopped by user.")

    except Exception as e:
        logging.error(f"Error in monitoring loop: {str(e)}")
        print(f"Fatal error in monitoring loop: {str(e)}")

if __name__ == "__main__":
    try:
        # Initialize logging
        print("Starting Zimbra Malicious Email Scanner...")
        logging.info("Starting Zimbra Malicious Email Scanner...")

        # Start monitoring
        monitor_directory()
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        print(f"Fatal error: {str(e)}")

def get_message_timestamps(mailbox, message_id):
    """Get the received timestamp for a message."""
    command = f"su - zimbra -c \"zmmailbox -z -m {mailbox} gm {message_id}\""
    output = run_zimbra_command(command)

    if not output:
        return None

    # Try to extract date from the output
    received_date = None
    date_match = re.search(r'Date:\s+(.*?)(?:\n|$)', output)
    if date_match:
        received_date = date_match.group(1).strip()

    return received_date

def search_most_recent_email(mailbox, from_address=None, subject=None):
    """Search for the most recent email matching the criteria."""
    search_criteria = []

    if from_address:
        # Clean up the from address for the search query
        clean_from = from_address.replace('<', '').replace('>', '')
        clean_from = clean_from.replace('"', '\\"')
        search_criteria.append(f'from:"{clean_from}"')

    if subject:
        # Escape special characters in subject
        clean_subject = subject.replace('"', '\\"')
        search_criteria.append(f'subject:"{clean_subject}"')

    # Add a time constraint to get recent emails
    search_criteria.append('after:-7day')

    # Build the search query
    search_query = " ".join(search_criteria)
    command = f'su - zimbra -c "zmmailbox -z -m {mailbox} s -t message \'{search_query}\'"'

    print(f"Searching with fallback criteria: {search_query}")
    output = run_zimbra_command(command)

    # Extract message IDs from the search results
    message_ids = extract_all_message_ids(output) if output else []

    # Return the first (most recent) message ID if any were found
    if message_ids:
        return message_ids[0]

    return None