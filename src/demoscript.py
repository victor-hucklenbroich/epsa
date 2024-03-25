import os

import pss
import sourcemodifier

LOG_PREFIX: str = "[PSS] "
BASE_PATH: str = os.path.join(os.getcwd(), 'data')
DATA_PATH: str = os.path.join(BASE_PATH, 'o')


def obfuscation_demo():
    pass


def harmonization_demo():
    pass


def get_project_paths() -> (str, str):
    p0 = os.path.join(DATA_PATH, "p0")
    p1 = os.path.join(DATA_PATH, "p1")
    return p0, p1


if __name__ == '__main__':
    (p0, p1) = get_project_paths()
    print(pss.LOG_PREFIX + "Unmodified PSS execution:")
    pss.compare(p0, p1)

    mmode = sourcemodifier.ModMode.OBFUSCATE
    print(LOG_PREFIX + " modifying " + p0 + " using mode: " + mmode.value)
    sourcemodifier.modify(p0, mode=mmode)

    print(pss.LOG_PREFIX + "Modified PSS execution:")
    pss.compare(p0, p1)
