import pickle
import time

import pss
from constants import *
from src import logger, genetics


def compare_to_repo(features: (list, list)):
    comparisons: [dict] = []
    for p1 in REPO_DATA:
        name: str = p1['name'] + "[O" + str(p1['optimization']) + "]"
        pss_value: float = pss.compare(features[0], features[1], p1['v'], p1['w'])
        comparison: dict = dict(name=name, pss=pss_value)
        comparisons.append(comparison)

    comparisons.sort(key=lambda comp: comp.get('pss'), reverse=True)
    for comparison in comparisons:
        logger.log("pss(" + TEST_PROGRAM + "[O" + str(O_LEVEL) + "]*, " + comparison.get('name') + ") = " + str(
            comparison.get('pss')), level=3)
    with open(os.path.join(RESULT_PATH, "comparisons"), "wb") as f:
        pickle.dump(comparisons, f)
        logger.log("saved comparisons to file: " + f.name, level=2)


def run_evo(target: str, target_o: int):
    # targeted project has to be defined in constants or when demo is called
    test: str = TEST_PROGRAM + "[O" + str(O_LEVEL) + "]"
    mode: str = str(MODE.name)
    logger.log("TEST_P: " + test, level=3)
    logger.log("TARGET_P: " + target + "[O" + str(target_o) + "]", level=3)
    logger.log("MODE: " + mode, level=3)
    target_features: (list, list) = find_entry(target, target_o)["v"], find_entry(target, target_o)["w"]
    unmodified_features: (list, list) = find_entry(TEST_PROGRAM, O_LEVEL)["v"], find_entry(TEST_PROGRAM, O_LEVEL)["w"]
    modified_features: (list, list) = genetics.run(target_features=target_features)
    logger.log(
        "initial pss = " + str(
            pss.compare(target_features[0], target_features[1], unmodified_features[0], unmodified_features[1])),
        level=3)
    logger.log("final pss = " + str(
        pss.compare(target_features[0], target_features[1], modified_features[0], modified_features[1])),
               level=3)
    compare_to_repo(modified_features)


def obfuscation_demo():
    run_evo(TEST_PROGRAM, O_LEVEL)


def harmonization_demo():
    run_evo(TARGET['name'], TARGET['optimization'])


if __name__ == '__main__':
    mkdir_cmd = ['mkdir', '-p', RESULT_PATH]
    subprocess.run(mkdir_cmd)
    start_time: float = time.time()
    if MODE == ModMode.OBFUSCATE:
        obfuscation_demo()
    else:
        harmonization_demo()
    logger.log("execution took " + str(round(time.time() - start_time, 2)) + " seconds", level=3)
