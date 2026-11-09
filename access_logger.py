import logging
import os

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "access.log")

logger = logging.getLogger("SDN_Access")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


def log_access(client_ip, action, message):
    logger.info(
        "Client: %s | Action: %s | Details: %s",
        client_ip, action, message
    )


def log_security_event(client_ip, message):
    logger.warning(
        "Client: %s | Security Event: %s",
        client_ip, message
    )
