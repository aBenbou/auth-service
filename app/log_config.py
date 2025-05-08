import logging
from logging.handlers import RotatingFileHandler

import boto3
import watchtower
from flask import g, has_request_context


# Custom Formatter
class RequestFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            record.request_id = g.get('request_id', 'no-request-id')
        else:
            record.request_id = 'N/A'  # Outside of Flask request context
        return super(RequestFormatter, self).format(record)

def configure_logging(app):
    logger = logging.getLogger('AuthService')
    logger.setLevel(logging.DEBUG)
    
    formatter = RequestFormatter(
        '[%(asctime)s] [Request ID: %(request_id)s] %(levelname)s - %(message)s (%(filename)s:%(lineno)d)'
    )
    environment = app.config.get('ENVIRONMENT', 'local')

    log_group = "auth-service-log-group"
    
    # Other handlers like RotatingFileHandler could be initialized here similarly
    file_handler = RotatingFileHandler('auth_service.log', maxBytes=10000, backupCount=1)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    region_name = "us-east-1"
    session = boto3.session.Session(region_name=region_name)
    cloudwatch_client = session.client('logs', region_name=region_name)
    
    cw_handler = watchtower.CloudWatchLogHandler(boto3_client=cloudwatch_client, log_group=log_group)
    cw_handler.setFormatter(formatter)
    logger.addHandler(cw_handler)

    app.logger = logger
    
    return logger
