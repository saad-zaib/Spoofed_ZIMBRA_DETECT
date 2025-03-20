#!/usr/bin/env python3
import os
import time
import logging
from logger import setup_logging
from file_handling import find_email_files
from email_analysis import process_email
from zimbra_operations import cleanup_processed_emails

def monitor_directory(base_path):
    """Monitor Zimbra email store directory in real-time."""
    processed_emails = {}  # Dictionary to track processed emails with timestamps
    print(f"Starting to monitor directory: {base_path}")
    logging.info(f"Starting monitoring of {base_path}")

    # Initial scan
    email_files = find_email_files(base_path)
    print(f"Initial scan found {len(email_files)} files")

    try:
        while True:
            email_files = find_email_files(base_path)
            new_emails_found = 0

            for email_file in email_files:
                if process_email(email_file, processed_emails):
                    new_emails_found += 1

            if new_emails_found > 0:
                print(f"Processed {new_emails_found} new emails")
            else:
                print("No new emails found in this scan")

            # Cleanup old entries every hour to prevent memory bloat
            cleanup_processed_emails(processed_emails)

            print(f"Waiting 5 seconds before next scan... (Total processed: {len(processed_emails)})")
            time.sleep(5)  # Adjust polling interval as needed
    except KeyboardInterrupt:
        print("Monitoring stopped by user")
        logging.info("Monitoring stopped by user")
    except Exception as e:
        print(f"Error during monitoring: {e}")
        logging.error(f"Error during monitoring: {e}")

if __name__ == "__main__":
    setup_logging()
    print("======= Zimbra Email Spoofing Detection with Tagging =======")
    print("Starting at:", time.strftime("%Y-%m-%d %H:%M:%S"))
    logging.info("Script started")

    base_path = '/opt/zimbra/store/'
    monitor_directory(base_path)