import json
import random
import string
import subprocess

import preprocessor as preproc
from src import logger, constants


def obfuscate(p: str, noise_per_loc: float = 0.1):
    logger.log("noise per LOC: " + str(noise_per_loc), level=1)
    sources: [str] = preproc.search_paths(p)
    noise_added: int = 0
    for source in sources:
        generated_functions = []
        loc: int = calculate_loc(source)
        for i in range(int(loc * noise_per_loc)):
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


def calculate_loc(source: str) -> int:
    scc_cmd = [constants.scc()]
    scc_cmd += [source, '-f', 'json']

    data = json.loads(constants.decode(subprocess.check_output(scc_cmd)))
    return data[0]['Code']
