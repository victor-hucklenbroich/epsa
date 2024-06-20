import time

import preprocessor as preproc
import pss
from constants import *
from src import logger, obfuscator, genetics
from src.genetics import Gene


def obfuscation_demo():
    preproc.clean(Path(TEST_PROGRAM_PATH), replace_with_archives=True)
    clone: dict = find_entry(TEST_PROGRAM, O_LEVEL)
    features: (list, list) = clone['v'], clone['w']
    obfuscator.obfuscate(TEST_PROGRAM_PATH, features)
    compare_to_repo()


def harmonization_demo():
    pass


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
    pop: list = genetics.initial_population(TEST_PROGRAM_PATH, POPULATION_SIZE)
    i: int = 0
    genes: [Gene] = []
    while i < 10:
        gene: Gene = genetics.generate_statement_gene()
        print(gene.get_content())
        genes.append(gene)
        i += 1
    x = 0
