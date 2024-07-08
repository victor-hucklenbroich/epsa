import locale
import os
import subprocess
from datetime import datetime
from enum import Enum
from pathlib import Path

import pandas as pd

# General
WORKING_DIR: str = str(Path(os.getcwd()).parent)


# Logging
class LogLevel(Enum):
    INFO = 2
    DEBUG = 1
    ALL = 0


LOG_LEVEL: LogLevel = LogLevel.INFO
LOG_DIR = os.path.join(WORKING_DIR, 'logs')
LOG_FILE = os.path.join(LOG_DIR, datetime.now().ctime().strip() + '.log')
LOG_PREFIX_PSS: str = "[PSS] "
LOG_PREFIX_MOD: str = "[MOD] "


def find_entry(name: str, o: int) -> dict:
    for entry in REPO_DATA:
        if entry['name'] == name and entry['optimization'] == o:
            return entry


# Test data
BASE_DATA_PATH: str = os.path.join(WORKING_DIR, 'data')
DEMO_DATA_PATH: str = os.path.join(BASE_DATA_PATH, 'demo')
REPO_DATA: list = pd.read_pickle(os.path.join(BASE_DATA_PATH, "BO_REPO_DATA"))
TEST_PROGRAM: str = "lua"
O_LEVEL: int = 0
TEST_PROGRAM_PATH: str = os.path.join(DEMO_DATA_PATH, TEST_PROGRAM)
TEST_SOURCES_PATH: str = os.path.join(TEST_PROGRAM_PATH, "src")
ARCHIVE_PATH: str = TEST_PROGRAM_PATH + "[O" + str(O_LEVEL) + "].zip"
BINARY_PATH: str = os.path.join(TEST_SOURCES_PATH, TEST_PROGRAM)
FEATURES: (list, list) = find_entry(TEST_PROGRAM, O_LEVEL)["v"], find_entry(TEST_PROGRAM, O_LEVEL)["w"]


# Genetics
POPULATION_SIZE: int = 10
GENERATIONS: int = 2
NOISE_HEADER: str = TEST_PROGRAM + "noise"


# Dependencies
def check_dependency(dependency: str):
    path = decode(subprocess.check_output(['which', dependency]))
    if path.find(dependency) < 0:
        raise Exception(dependency + ' not found in $PATH.')
    else:
        return path.replace('\n', '')


def decode(bytes) -> str:
    encoding = locale.getdefaultlocale()[1]
    return bytes.decode(encoding)


def gcc():
    return check_dependency('gcc')


def make():
    return check_dependency('make')


def scc():
    return check_dependency('scc')
