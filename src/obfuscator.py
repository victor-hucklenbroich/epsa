import json
import random
import string
import subprocess
import time

import preprocessor as preproc
from src import logger, constants


def obfuscate(p: str, noise_per_loc: float = 0.1):
    start_time = time.time()
    logger.log("noise per LOC: " + str(noise_per_loc), level=1, prefix=constants.LOG_PREFIX_MOD)
    sources: [str] = preproc.search_paths(p)
    total_noise_added: int = 0
    total_calls_added: int = 0
    for source in sources:
        loc: int = calculate_loc(source)
        (declarations, functions) = generate_functions(source, int(loc * noise_per_loc))
        with open(source, "r") as s:
            lines = s.readlines()

        total_noise_added += len(functions)
        total_calls_added += generate_calls(source, lines, functions)
        lines.insert(0, declarations)

        with open(source, "w") as s:
            s.writelines(lines)
            logger.log("Written noise to source file: " + source, prefix=constants.LOG_PREFIX_MOD)

    logger.log(
        "obfuscated sources in " + p + " by adding " + str(
            total_noise_added) + " noise functions and calling them " + str(
            total_calls_added) + " times", level=1,
        prefix=constants.LOG_PREFIX_MOD)
    logger.log("modification took " + str(round(time.time() - start_time, 2)) + " seconds\n", level=1,
               prefix=constants.LOG_PREFIX_MOD)


def calculate_loc(source: str) -> int:
    scc_cmd = [constants.scc()]
    scc_cmd += [source, '-f', 'json']

    data = json.loads(constants.decode(subprocess.check_output(scc_cmd)))
    loc: int = data[0]['Code']
    logger.log("Found " + str(loc) + " logical lines of code in " + source, prefix=constants.LOG_PREFIX_MOD)
    return loc


def generate_functions(source: str, amount_of_noise: int) -> (str, [dict]):
    declarations: str = ""
    generated_functions = []
    for i in range(amount_of_noise):
        generated_functions += [generate_function(generated_functions)]

    for function in generated_functions:
        declarations += function["function"]
        logger.log("Generated noise function " + function["name"] + "() for " + source, prefix=constants.LOG_PREFIX_MOD)

    return declarations, generated_functions


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


def generate_calls(source: str, lines: [str], functions: [dict]) -> int:
    calls_added: int = 0
    for i in range(len(lines)):
        line = lines[i]
        if (") {" in line or "){" in line) and "#" not in line and ";" and "\\" not in line and "}" not in line:
            function = random.choice(functions)["name"] + "();"
            line = line[:len(line) - 1]
            line += " " + function + "\n"
            logger.log("Modified line " + str(
                i + len(functions) + 1) + " (" + str(
                i + 1) + ") in " + source + " by adding call to noise function " + function,
                       prefix=constants.LOG_PREFIX_MOD)
            calls_added += 1
        lines[i] = line

    return calls_added
