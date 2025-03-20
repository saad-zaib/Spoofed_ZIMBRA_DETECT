#!/usr/bin/env python3
import re
import time
import socket
import logging
import dns.resolver
from file_handling import extract_email_headers
from zimbra_operations import (
    extract_email_info, search_specific_email, create_tag, 
    check_if_email_already_tagged, add_to_spoofed_tag, get_message_timestamps,
    search_most_recent_email
)

def check_spoofing(msg):
    """Analyze the email headers to detect spoofing."""
    from_header = msg.get('From', '')
    return_path = msg.get('Return-Path', '')
    received_headers = msg.get_all('Received', [])
    subject = msg.get('Subject', '(No Subject)')
    spf_pass = False
    dkim_pass = False
    dmarc_pass = False
    reverse_dns_pass = False
    header_mismatch = False
    spoofing_detected = False

    print(f"\nAnalyzing email - From: {from_header} - Subject: {subject}")
    print(f"Return-Path: {return_path}")

    # Extract domain from the "From" header
    match = re.search(r'@([a-zA-Z0-9.-]+)', from_header)
    domain = match.group(1) if match else None
    print(f"Extracted domain: {domain}")

    if domain:
        try:
            # Check SPF record
            print(f"Checking SPF record for {domain}...")
            try:
                answers = dns.resolver.resolve(f"{domain}", 'TXT')
                for txt_record in answers:
                    record_text = txt_record.to_text()
                    print(f"SPF TXT record: {record_text}")
                    if "v=spf1" in record_text:
                        spf_pass = True
                        print("SPF record found")
            except Exception as e:
                print(f"SPF lookup failed: {e}")

            # Check DMARC record
            print(f"Checking DMARC record for {domain}...")
            try:
                answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
                for txt_record in answers:
                    record_text = txt_record.to_text()
                    print(f"DMARC TXT record: {record_text}")
                    if "v=DMARC1" in record_text:
                        dmarc_pass = True
                        print("DMARC record found")
            except Exception as e:
                print(f"DMARC lookup failed: {e}")
        except Exception as e:
            print(f"DNS lookup error: {e}")

    # Check DKIM (basic check for DKIM-Signature header presence)
    if 'DKIM-Signature' in msg:
        dkim_pass = True
        print("DKIM-Signature header found")
    else:
        print("No DKIM-Signature header found")

    # Reverse DNS lookup check
    if received_headers:
        last_received = received_headers[-1]
        print(f"Last received header: {last_received}")
        match_ip = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', last_received)
        if match_ip:
            ip_address = match_ip.group(1)
            print(f"Source IP address: {ip_address}")
            try:
                reverse_dns = socket.gethostbyaddr(ip_address)[0]
                print(f"Reverse DNS: {reverse_dns}")
                if domain and domain in reverse_dns:
                    reverse_dns_pass = True
                    print("Reverse DNS check passed")
                else:
                    print(f"Reverse DNS does not match sender domain {domain}")
            except socket.herror as e:
                print(f"Reverse DNS lookup failed: {e}")

    # Header mismatch detection
    if return_path and domain and domain not in return_path:
        header_mismatch = True
        print(f"Header mismatch detected: Return-Path {return_path} doesn't match From domain {domain}")

    # Enhanced spoofing detection logic
    if not spf_pass or not dkim_pass or not dmarc_pass or not reverse_dns_pass or header_mismatch:
        spoofing_detected = True
        print("SPOOFING DETECTED: One or more security checks failed")
    else:
        print("All security checks passed, no spoofing detected")

    return {
        'from': from_header,
        'return_path': return_path,
        'subject': subject,
        'spf_pass': spf_pass,
        'dkim_pass': dkim_pass,
        'dmarc_pass': dmarc_pass,
        'reverse_dns_pass': reverse_dns_pass,
        'header_mismatch': header_mismatch,
        'spoofing_detected': spoofing_detected
    }

def process_email(email_path, processed_emails):
    """Process a single email file with improved identification."""
    msg = extract_email_headers(email_path)
    if not msg:
        return False

    # Extract message ID and headers for uniqueness checking
    message_id_header = msg.get('Message-ID', '')
    from_header = msg.get('From', '')
    subject = msg.get('Subject', '')
    date_header = msg.get('Date', '')

    # Generate a unique ID based on headers
    email_signature = f"{message_id_header}|{from_header}|{subject}|{date_header}"

    # Check if we've already processed this exact email
    if email_signature in processed_emails:
        print(f"Already processed email: {email_signature}")
        return False

    results = check_spoofing(msg)

    if results['spoofing_detected']:
        log_message = (f"Potential spoof detected in {email_path}\n"
                      f"From: {results['from']}\n"
                      f"Subject: {results['subject']}\n"
                      f"Return-Path: {results['return_path']}\n"
                      f"SPF Pass: {results['spf_pass']}, DKIM Pass: {results['dkim_pass']}, DMARC Pass: {results['dmarc_pass']}\n"
                      f"Reverse DNS Pass: {results['reverse_dns_pass']}, Header Mismatch: {results['header_mismatch']}\n"
                      "-------------------------")
        print(log_message)
        logging.warning(log_message)

        # Extract detailed email info for tagging
        email_info = extract_email_info(email_path, msg)

        if email_info and email_info.get('mailbox'):
            mailbox = email_info['mailbox']
            print(f"Tagging email for mailbox: {mailbox}")

            # Make sure the SPOOFED tag exists
            if create_tag(mailbox):
                # Search for the specific email using precise criteria
                message_id = search_specific_email(mailbox, email_info)

                if message_id:
                    # Check if the message is already tagged before attempting to tag it
                    if check_if_email_already_tagged(mailbox, message_id):
                        print(f"Message {message_id} is already tagged with SPOOFED, skipping")
                    else:
                        if add_to_spoofed_tag(mailbox, message_id):
                            print(f"Successfully tagged message {message_id} as SPOOFED")
                            # Add to processed emails with timestamp
                            received_date = get_message_timestamps(mailbox, message_id)
                            processed_emails[email_signature] = {
                                'message_id': message_id,
                                'tagged_timestamp': time.time(),
                                'received_date': received_date
                            }
                        else:
                            print(f"Failed to tag message {message_id}")
                else:
                    print("Could not find the specific message in the mailbox")

                    # Fallback to the old method if precise search fails
                    print("Trying fallback search method...")
                    message_id = search_most_recent_email(
                        mailbox,
                        from_address=email_info['from'],
                        subject=email_info['subject']
                    )

                    if message_id:
                        print(f"Warning: Using fallback method. Found message ID: {message_id}")
                        if check_if_email_already_tagged(mailbox, message_id):
                            print(f"Message {message_id} is already tagged with SPOOFED, skipping")
                        else:
                            if add_to_spoofed_tag(mailbox, message_id):
                                print(f"Successfully tagged message {message_id} as SPOOFED (using fallback method)")
                                # Add to processed emails with timestamp
                                received_date = get_message_timestamps(mailbox, message_id)
                                processed_emails[email_signature] = {
                                    'message_id': message_id,
                                    'tagged_timestamp': time.time(),
                                    'received_date': received_date
                                }
                            else:
                                print(f"Failed to tag message {message_id}")
                    else:
                        print("Could not find any matching message even with fallback method")
            else:
                print("Failed to create SPOOFED tag")

    # Mark as processed even if it wasn't spoofed
    processed_emails[email_signature] = {
        'message_id': None,  # No message ID if not spoofed or not found
        'processed_timestamp': time.time(),
        'spoofed': results['spoofing_detected']
    }

    return True