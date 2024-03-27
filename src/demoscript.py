import os

import preprocessor as preproc
import pss
import sourcemodifier
from constants import PROJECTS_PATH
from src import logger


def obfuscation_demo():
    pass


def harmonization_demo():
    pass


def get_project_paths() -> (str, str):
    p0 = os.path.join(PROJECTS_PATH, "p0")
    p1 = os.path.join(PROJECTS_PATH, "p1")
    return p0, p1


if __name__ == '__main__':
    preproc.clean(replace_with_archives=True)
    (p0, p1) = get_project_paths()
    logger.log(
        "########################################## Pre modification execution ##########################################\n",
        level=1)
    pss.compare(p0, p1)
    logger.log(
        "############################################# Source modification ##############################################\n",
        level=1)
    mmode = sourcemodifier.ModMode.OBFUSCATE
    logger.log("modifying " + p0 + "using mode " + mmode.value)
    sourcemodifier.modify(p0, mode=mmode)

    logger.log(
        "########################################## Post modification execution ##########################################\n",
        level=1)
    preproc.clean()
    pss.compare(p0, p1)
