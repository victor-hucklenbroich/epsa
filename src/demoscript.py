from pathlib import Path

import pandas as pd

import preprocessor as preproc
import pss
import sourcemodifier
from constants import *
from sourcemodifier import ModMode
from src import logger


def obfuscation_demo():
    path: Path = Path(BASE_DATA_PATH)
    (p0, p1) = get_project_paths()
    preproc.clean(path, replace_with_archives=True)
    sourcemodifier.modify(p0, mode=ModMode.OBFUSCATE)
    preproc.clean(path)
    self = TEST_PROGRAM + "*", pss.compare(p0, p1)
    clone = find_worst_clone(TEST_PROGRAM)
    best = find_best(TEST_PROGRAM)
    non_clone = find_best_non_clone(TEST_PROGRAM)
    logger.log(format_results(("", self[0], self[1]), ("best value", best[0], best[1]),
                              ("best non-clone", non_clone[0], non_clone[1]), ("worst clone", clone[0], clone[1])),
               level=1)


def harmonization_demo():
    return


def get_project_paths() -> (str, str):
    p1 = os.path.join(DEMO_DATA_PATH, TEST_PROGRAM)
    p0 = p1 + "*"
    return p0, p1


def read_repo_data() -> dict:
    return pd.read_pickle(REPO_DATA_PATH)


def find_entry(id: str, o: int) -> dict:
    data = read_repo_data()
    for i in data:
        entry = data[i]
        try:
            if entry[0][0] == id and entry[0][2] == ('O' + str(o)):
                return entry
        except KeyError:
            continue

    return {}


def find_best(id: str, optimization: int = 0) -> (str, float):
    entry = find_entry(id, optimization)
    max: float = 0.0
    name: str = ""
    for i in entry:
        value = pss.calculate(entry[i][4])
        if value > max:
            max = value
            name = entry[i][1]

    return name, max


def find_best_non_clone(id: str, optimization: int = 0) -> (str, float):
    entry = find_entry(id, optimization)
    max: float = 0.0
    name: str = ""
    for i in entry:
        value = pss.calculate(entry[i][4])
        if value > max and entry[i][1] != id:
            max = value
            name = entry[i][1]

    return name, max


def find_worst_clone(id: str, optimization: int = 0) -> (str, float):
    entry = find_entry(id, optimization)
    min: float = 1.0
    name: str = ""
    for i in entry:
        value = pss.calculate(entry[i][4])
        if value < min and entry[i][1] == id:
            min = value
            name = entry[i][1]

    return name, min


def format_results(*results: (str, str, float)) -> str:
    output: str = TEST_PROGRAM + " PSS compared to: \n"
    for result in results:
        output += "| " + result[1] + " = " + str(round(result[2], 4)) + (
            (" (" + result[0] + ")") if result[0] != "" else "") + "\n"

    return output


if __name__ == '__main__':
    obfuscation_demo()
