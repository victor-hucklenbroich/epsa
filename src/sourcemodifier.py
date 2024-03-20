from enum import Enum

ModMode = Enum('Harmonize', 'Obfuscate')


def modify(*p: str, mode: ModMode = 'Obfuscate'):
    if mode is 'Obfuscate':
        obfuscate(p[0])
    elif mode is 'Harmonize':
        harmonize(p[0], p[1])
    else:
        pass


def harmonize(p0: str, p1: str):
    pass


def obfuscate(p: str):
    pass
