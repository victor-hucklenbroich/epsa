import pickle
import time

import preprocessor as preproc
import pss
from constants import *
from src import logger, genetics


def compare_to_repo():
    preproc.clean(Path(TEST_PROGRAM_PATH))
    (v0, w0) = pss.compute_features(TEST_PROGRAM_PATH)
    comparisons: [dict] = []
    for p1 in REPO_DATA:
        name: str = p1['name'] + "[" + p1['optimization'] + "]"
        pss_value: float = pss.compare(v0, w0, p1['v'], p1['w'])
        comparison: dict = dict(name=name, pss=pss_value)
        comparisons.append(comparison)

    comparisons.sort(key=lambda c: c.get('pss'))
    for comparison in comparisons:
        logger.log("pss(" + TEST_PROGRAM + "*, " + comparison.get('name') + ") = " + str(comparison.get('pss')),
                   level=1)


def run_evo(target: str = TARGET_PROGRAM, target_o: int = TARGET_PROGRAM_O):
    # targeted project has to be defined in constants or when demo is called
    test: str = TEST_PROGRAM + "[O" + str(O_LEVEL) + "]"
    mode: str = str(genetics.mode.name)
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
    with open(os.path.join(BASE_DATA_PATH, 'results',
                           genetics.mode.name[0] + ":" + test + ":" + target + ";" + str(datetime.now())), "wb") as f:
        pickle.dump({"v": modified_features[0], "w": modified_features[1]}, f)
        logger.log("saved features to file: " + f.name, level=2)


if __name__ == '__main__':
    i: int = 0
    for entry in REPO_DATA:
        logger.log("\nrun: " + str(i), level=3)
        t: str = entry['name']
        o: int = entry['optimization']
        start_time: float = time.time()
        run_evo(target=t, target_o=o)
        logger.log("execution took " + str(round(time.time() - start_time, 2)) + " seconds", level=3)
        i += 1
