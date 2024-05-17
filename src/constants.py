import locale
import os
import subprocess
from pathlib import Path

import pandas as pd
import numpy as np

from datetime import datetime

# General
WORKING_DIR: str = str(Path(os.getcwd()).parent)


# Logging
LOG_DIR = os.path.join(WORKING_DIR, 'logs')
LOG_FILE = os.path.join(LOG_DIR, datetime.now().ctime().strip() + '.log')
LOG_PREFIX_PSS: str = "[PSS] "
LOG_PREFIX_MOD: str = "[MOD] "


# Test data
BASE_DATA_PATH: str = os.path.join(WORKING_DIR, 'data')
DEMO_DATA_PATH: str = os.path.join(BASE_DATA_PATH, 'demo')
REPO_DATA_OPTIMIZED: str = os.path.join(BASE_DATA_PATH, 'BO_MD')
REPO_DATA_FEATURES: str = os.path.join(BASE_DATA_PATH, 'A_BO')
REPO_DATA_CORRECTED: str = os.path.join(BASE_DATA_PATH, 'A_BO_C')
TEST_PROGRAM: str = "lua"
ARCHIVE_PATH: str = os.path.join(BASE_DATA_PATH, TEST_PROGRAM) + "_o.zip"


def repo_data() -> [dict]:
    data: list = []
    BO_MD = read_pickle_data(REPO_DATA_OPTIMIZED)
    A_BO = read_pickle_data(REPO_DATA_FEATURES)
    A_BO_C = read_pickle_data(REPO_DATA_CORRECTED)
    for i in BO_MD:
        j: int = i + 1
        if j >= len(BO_MD):
            j -= 2
        name: str = BO_MD[i][j][0]
        optimization: str = BO_MD[i][j][2]
        v: list = np.ndarray.tolist(A_BO.get(str(i))[0])
        w: list = np.ndarray.tolist(A_BO.get(str(i))[2])
        if i == 5 or i == 6 or i == 12:
            v = np.ndarray.tolist(A_BO_C.get(str(i))[0])
            w = np.ndarray.tolist(A_BO_C.get(str(i))[2])

        entry: dict = dict(name=name, optimization=optimization, v=v, w=w)
        data.append(entry)

    return data


def read_pickle_data(path: str) -> dict:
    return pd.read_pickle(path)


# Obfuscation
POPULATION_SIZE: int = 10
EVOLUTION_CYCLES: int = 10


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
