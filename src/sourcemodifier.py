from enum import Enum

from constants import TEST_PROGRAM
from harmonizer import harmonize
from obfuscator import obfuscate
from src import logger


class ModMode(Enum):
    OBFUSCATE = 'OBFUSCATE'
    HARMONIZE = 'HARMONIZE'


def modify(*p: str, mode: ModMode = ModMode.OBFUSCATE):
    logger.log("modifying " + TEST_PROGRAM + "* using mode " + mode.value)
    if mode is ModMode.OBFUSCATE:
        obfuscate(p[0])
    elif mode is ModMode.HARMONIZE:
        harmonize(p[0], p[1])
