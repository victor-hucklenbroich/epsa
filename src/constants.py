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


def find_entry(name: str, o: int) -> dict:
    for entry in REPO_DATA:
        if entry['name'] == name and entry['optimization'] == o:
            return entry


# Test data
BASE_DATA_PATH: str = os.path.join(WORKING_DIR, 'data')
DEMO_DATA_PATH: str = os.path.join(BASE_DATA_PATH, 'demo')
CONFIG: dict = pd.read_pickle(os.path.join(BASE_DATA_PATH, 'config'))
ARCHIVE_PATH: str = os.path.join(DEMO_DATA_PATH, CONFIG["arch"])
REPO_DATA: list = pd.read_pickle(os.path.join(BASE_DATA_PATH, "BO_REPO_DATA"))
TEST_PROGRAM: str = CONFIG["name"]
TARGET_PROGRAM: str = "lua"
TARGET_PROGRAM_O: int = 0
O_LEVEL: int = CONFIG["o"]
TEST_PROGRAM_PATH: str = os.path.join(DEMO_DATA_PATH, TEST_PROGRAM)
TEST_SOURCES_PATH: str = os.path.join(TEST_PROGRAM_PATH, "src")
BINARY_PATH: str = os.path.join(TEST_SOURCES_PATH, TEST_PROGRAM)
FEATURES: (list, list) = (find_entry(TARGET_PROGRAM, TARGET_PROGRAM_O)["v"],
                          find_entry(TARGET_PROGRAM, TARGET_PROGRAM_O)["w"])

# Genetics
POPULATION_SIZE: int = 10
GENERATIONS: int = 10
SELECTION_RATIO: float = 0.4
MIN_FITNESS: float = -10000
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
