import locale
import os
import subprocess
from datetime import datetime

# Test data
BASE_DATA_PATH: str = os.path.join(os.getcwd(), 'data')
PROJECTS_PATH: str = os.path.join(BASE_DATA_PATH, 'o')

# Logging
LOG_DIR = os.path.join(os.getcwd(), 'logs')
LOG_FILE = os.path.join(LOG_DIR, datetime.now().ctime().strip() + '.log')
LOG_PREFIX: str = "[PSS] "


def gcc():
    return check_dependency('gcc')


def make():
    return check_dependency('make')


def scc():
    return check_dependency('scc')


def decode(bytes) -> str:
    encoding = locale.getdefaultlocale()[1]
    return bytes.decode(encoding)


def check_dependency(dependency: str):
    path = decode(subprocess.check_output(['which', dependency]))
    if path.find(dependency) < 0:
        raise Exception(dependency + ' not found in $PATH.')
    else:
        return path.replace('\n', '')
