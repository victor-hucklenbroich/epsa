import os

import pss
import sourcemodifier

LOG_PREFIX: str = "[PSS] "
BASE_PATH: str = os.path.join(os.getcwd(), 'data')
DATA_PATH: str = BASE_PATH


def obfuscation_demo():
    pass


def harmonization_demo():
    pass


def get_project_paths() -> (str, str):
    p0 = os.path.join(DATA_PATH, "p0")
    p1 = os.path.join(DATA_PATH, "p1")
    return p0, p1


if __name__ == '__main__':
    DATA_PATH = os.path.join(BASE_PATH, 'o')
    (p0, p1) = get_project_paths()
    print(pss.LOG_PREFIX + "Unmodified PSS execution:")
    pss.compare(p0, p1)

    print(LOG_PREFIX + "Obfuscating p0")
    sourcemodifier.modify(p0)

    print(pss.LOG_PREFIX + "Modified PSS execution:")
    pss.compare(p0, p1)
