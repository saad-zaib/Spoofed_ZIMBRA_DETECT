#!/usr/bin/env python3
import os
import sys
import json
import logging
import datetime
from logging.handlers import RotatingFileHandler

class JsonFormatter(logging.Formatter):
    """Custom formatter that outputs log records as JSON."""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S'),
            'level': record.levelname,
            'message': record.getMessage(),
        }
        
        # Add extra attributes if they exist
        if hasattr(record, 'email_data') and record.email_data:
            log_entry['email_data'] = record.email_data
            
        return json.dumps(log_entry)

class TeeOutput:
    """Class to duplicate output to both console and logger."""
    def __init__(self, logger, log_level=logging.INFO):
        self.terminal = sys.stdout
        self.logger = logger
        self.log_level = log_level
        
    def write(self, message):
        self.terminal.write(message)
        # Only log non-empty lines
        message = message.strip()
        if message:
            self.logger.log(self.log_level, message)
            
    def flush(self):
        self.terminal.flush()

def setup_logging():
    """Set up logging to both terminal and JSON file."""
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Clear any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Console handler with standard formatter
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # JSON file handler with JSON formatter
    json_log_path = '/var/log/spoofing.json'
    
    # Ensure the directory exists and is writable
    os.makedirs(os.path.dirname(json_log_path), exist_ok=True)
    
    # Use rotating file handler to prevent the log from growing too large
    json_handler = RotatingFileHandler(
        json_log_path, 
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    json_formatter = JsonFormatter()
    json_handler.setFormatter(json_formatter)
    logger.addHandler(json_handler)
    
    # Redirect stdout to both console and logger
    sys.stdout = TeeOutput(logger)
    
    # Redirect stderr to both console and logger (as warning level)
    sys.stderr = TeeOutput(logger, logging.WARNING)
    
    return logger

def log_email_analysis(email_data):
    """Log email analysis data with all details in JSON format."""
    logger = logging.getLogger()
    
    # Create a log record with the email data attached
    record = logging.LogRecord(
        name=logger.name,
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Email analysis results",
        args=(),
        exc_info=None
    )
    
    # Attach the email data to the record
    record.email_data = email_data
    
    # Process the record through all handlers
    for handler in logger.handlers:
        if isinstance(handler.formatter, JsonFormatter):
            handler.handle(record)