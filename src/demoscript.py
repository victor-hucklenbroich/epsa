import os
import time
from pathlib import Path

import preprocessor as preproc
import pss
import sourcemodifier
from constants import BASE_DATA_PATH
from sourcemodifier import ModMode
from src import logger


def demo(mmode: ModMode):
    path: Path
    if mmode is ModMode.OBFUSCATE:
        path = Path(os.path.join(BASE_DATA_PATH, 'o'))
        preproc.clean(path, replace_with_archives=True)
    elif mmode is ModMode.HARMONIZE:
        path = Path(os.path.join(BASE_DATA_PATH, 'h'))
        preproc.clean(path, replace_with_archives=True, clean_with_make=False)

    (p0, p1) = get_project_paths(path)
    logger.log(
        "########################################## Pre modification execution ##########################################\n",
        level=1)
    pss.compare(p0, p1)
    logger.log(
        "############################################# Source modification ##############################################\n",
        level=1)
    logger.log("modifying " + p0 + "using mode " + mmode.value)
    start_time = time.time()
    if mmode is ModMode.OBFUSCATE:
        sourcemodifier.modify(p0, mode=mmode)
    elif mmode is ModMode.HARMONIZE:
        sourcemodifier.modify(p0, p1, mode=mmode)

    logger.log("modification took " + str(round(time.time() - start_time, 2)) + " seconds\n", level=1)

    logger.log(
        "########################################## Post modification execution ##########################################\n",
        level=1)
    preproc.clean(path)
    pss.compare(p0, p1)


def obfuscation_demo():
    demo(ModMode.OBFUSCATE)


def harmonization_demo():
    demo(ModMode.HARMONIZE)


def get_project_paths(projectspath: str) -> (str, str):
    p0 = os.path.join(projectspath, "p0")
    p1 = os.path.join(projectspath, "p1")
    return p0, p1


if __name__ == '__main__':
    harmonization_demo()
