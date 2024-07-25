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


if __name__ == '__main__':
    test: str = TEST_PROGRAM + "[O" + str(O_LEVEL) + "]"
    target: str = TARGET_PROGRAM + "[O" + str(TARGET_PROGRAM_O) + "]"
    mode: str = str(genetics.mode.name)
    logger.log("TEST_P: " + test, level=2)
    logger.log("TARGET_P: " + target, level=2)
    logger.log("MODE: " + mode, level=2)
    unmodified_features: (list, list) = find_entry(TEST_PROGRAM, O_LEVEL)["v"], find_entry(TEST_PROGRAM, O_LEVEL)["w"]
    modified_features: (list, list) = genetics.run()
    logger.log(
        "initial pss = " + str(pss.compare(FEATURES[0], FEATURES[1], unmodified_features[0], unmodified_features[1])),
        level=2)
    logger.log("final pss = " + str(pss.compare(FEATURES[0], FEATURES[1], modified_features[0], modified_features[1])),
               level=2)
