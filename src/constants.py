import locale
import os
import random
import subprocess
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

import pandas as pd

# General
WORKING_DIR: str = str(Path(os.getcwd()).parent)


# Logging
class LogLevel(Enum):
    CRITICAL = 3
    INFO = 2
    DEBUG = 1
    ALL = 0


LOG_LEVEL: LogLevel = LogLevel.INFO
LOG_DIR = os.path.join(WORKING_DIR, 'logs')
LOG_FILE = os.path.join(LOG_DIR, datetime.now().ctime().strip() + '.log')


# Execution
class ModMode(Enum):
    OBFUSCATE = 0
    HARMONIZE = 1


MODE: ModMode = ModMode.HARMONIZE


def find_entry(name: str, o: int) -> dict:
    for entry in REPO_DATA:
        if entry['name'] == name and entry['optimization'] == o:
            return entry


def find_entries(project: str) -> list:
    entries: list = []
    for entry in REPO_DATA:
        if entry['project'] == project:
            entries.append(entry)
    return entries


# Test data
BASE_DATA_PATH: str = os.path.join(WORKING_DIR, 'data')
DEMO_DATA_PATH: str = os.path.join(BASE_DATA_PATH, 'demo')
CONFIG: dict = pd.read_pickle(os.path.join(BASE_DATA_PATH, 'config'))
ARCHIVE_PATH: str = os.path.join(DEMO_DATA_PATH, CONFIG["arch"])
REPO_DATA: list = pd.read_pickle(os.path.join(BASE_DATA_PATH, "BO_REPO_DATA"))
TEST_PROGRAM: str = CONFIG["name"]
O_LEVEL: int = CONFIG["o"]
COMPILE_TIME: float = CONFIG["ctime"]
TEST_PROGRAM_PATH: str = os.path.join(DEMO_DATA_PATH, TEST_PROGRAM)
TEST_SOURCES_PATH: str = os.path.join(TEST_PROGRAM_PATH, "src")
BINARY_PATH: str = os.path.join(TEST_PROGRAM_PATH, CONFIG["bin"])
TARGET: dict = random.choice(REPO_DATA)
RESULT_PATH: str = os.path.join(BASE_DATA_PATH, 'results', TEST_PROGRAM + "*[O" + str(O_LEVEL) + "]" + MODE.name[0] + (
    "-" + TARGET['name'] + "[O" + str(TARGET['optimization']) + "]" if MODE == ModMode.HARMONIZE else ""))

# Genetics
POPULATION_SIZE: int = 100
ELITE_SIZE: int = 10
SELECTION_RATIO: float = 0.22  # 4 / (1 + np.sqrt(1 + 8 * POPULATION_SIZE))
MIN_FITNESS: float = -10000
NOISE_HEADER: str = TEST_PROGRAM + "noise"
TIMEOUT: datetime = datetime.now() + timedelta(hours=10)
EXCLUSIONS: list = []

class NameUtil:
    def __init__(self):
        self.index: int = 0

    def get_next_name(self) -> str:
        self.index += 1
        return f'{self.index - 1:05d}'

NAME_UTIL: NameUtil = NameUtil()


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
