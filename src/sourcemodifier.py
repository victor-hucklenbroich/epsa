from enum import Enum

from harmonizer import harmonize
from obfuscator import obfuscate


class ModMode(Enum):
    OBFUSCATE = 'OBFUSCATE'
    HARMONIZE = 'HARMONIZE'


def modify(*p: str, mode: ModMode = ModMode.OBFUSCATE) -> str:
    if mode is ModMode.OBFUSCATE:
        obfuscate(p[0])
    elif mode is ModMode.HARMONIZE:
        harmonize(p[0], p[1])

    return mode.value
