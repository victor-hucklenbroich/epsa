import os
from datetime import datetime

# Test data
BASE_DATA_PATH: str = os.path.join(os.getcwd(), 'data')
PROJECTS_PATH: str = os.path.join(BASE_DATA_PATH, 'o')

# Logging
LOG_DIR = os.path.join(os.getcwd(), 'logs')
LOG_FILE = os.path.join(LOG_DIR, datetime.now().ctime().strip() + '.log')
LOG_PREFIX: str = "[PSS] "
