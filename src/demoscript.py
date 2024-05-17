import preprocessor as preproc
import pss
import sourcemodifier
from constants import *
from sourcemodifier import ModMode
from src import logger


def obfuscation_demo():
    path: Path = Path(BASE_DATA_PATH)
    p0 = get_project_paths()[0]
    preproc.clean(path, replace_with_archives=True)
    sourcemodifier.modify(p0, mode=ModMode.OBFUSCATE)
    preproc.clean(path)

    (v0, w0) = pss.compute_features(p0)
    comparisons: [dict] = []
    for p1 in repo_data():
        name: str = p1.get('name') + "[" + p1.get('optimization') + "]"
        pss_value: float = pss.compare_with_given_features(v0, w0, p1.get('v'), p1.get('w'))
        comparison: dict = dict(name=name + "", pss=pss_value)
        comparisons.append(comparison)

    comparisons.sort(key=lambda c: c.get('pss'))
    for comparison in comparisons:
        logger.log("pss(" + TEST_PROGRAM + "*, " + comparison.get('name') + ") = " + str(comparison.get('pss')), level=1)


def harmonization_demo():
    return


def get_project_paths() -> (str, str):
    p1 = os.path.join(DEMO_DATA_PATH, TEST_PROGRAM)
    p0 = p1 + "*"
    return p0, p1


if __name__ == '__main__':
    obfuscation_demo()
