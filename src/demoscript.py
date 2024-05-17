import preprocessor as preproc
import pss
import sourcemodifier
from constants import *
from sourcemodifier import ModMode


def obfuscation_demo():
    path: Path = Path(BASE_DATA_PATH)
    p0 = get_project_paths()[0]
    preproc.clean(path, replace_with_archives=True)
    sourcemodifier.modify(p0, mode=ModMode.OBFUSCATE)
    preproc.clean(path)

    (v0, w0) = pss.compute_features(p0)
    for p1 in repo_data():
        pss_value = pss.compare_with_given_features(v0, w0, p1.get('v'), p1.get('w'))


def harmonization_demo():
    return


def get_project_paths() -> (str, str):
    p1 = os.path.join(DEMO_DATA_PATH, TEST_PROGRAM)
    p0 = p1 + "*"
    return p0, p1


if __name__ == '__main__':
    obfuscation_demo()
