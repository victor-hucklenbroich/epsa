import random
import string
from enum import Enum

import preprocessor as preproc
from src import logger


class ModMode(Enum):
    OBFUSCATE = 'OBFUSCATE'
    HARMONIZE = 'HARMONIZE'


def modify(*p: str, mode: ModMode = ModMode.OBFUSCATE) -> str:
    if mode is ModMode.OBFUSCATE:
        obfuscate(p[0])
    elif mode is ModMode.HARMONIZE:
        harmonize(p[0], p[1])

    return mode.value


def harmonize(p0: str, p1: str):
    pass


def obfuscate(p: str, noise_per_loc: float = 0.1):
    logger.log("noise per LOC: " + str(noise_per_loc), level=1)
    sources: [str] = preproc.search_paths(p)
    noise_added: int = 0
    for source in sources:
        with open(source, 'r') as s:
            for count, line in enumerate(s):
                pass
        generated_functions = []
        for i in range(int(count * noise_per_loc)):
            generated_functions += [generate_function(generated_functions)]

        with open(source, "a") as s:
            s.write("\n")
            for func in generated_functions:
                s.write(func["function"])
                logger.log("Added noise function " + func["name"] + "() to " + source)
                noise_added += 1

            s.write("\n")

    logger.log("obfuscated sources in " + p + " by adding " + str(noise_added) + " noise functions\n", level=1)


def generate_function(available_functions: [dict]) -> dict:
    return_types = ['void', 'int', 'char']
    f_name: str = ''.join(random.choice(string.ascii_letters) for i in range(random.randint(5, 10)))
    f_return: str = random.choice(return_types)
    f_def: str = f_return + ' ' + f_name + '() { '
    if available_functions:
        for i in range(random.randint(0, 10)):
            call_f = random.choice(available_functions)
            f_def += call_f["name"]
            f_def += '(); '

    if f_return == 'void':
        pass
    else:
        f_def += 'return 0; '

    f_def += '} \n'
    return dict(name=f_name, return_type=f_return, function=f_def)
