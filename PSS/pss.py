import os
import time

import numpy as np

import preprocessor as preproc
import projectprocessor

DATA_PATH = os.path.join(os.getcwd(), 'data')
PSS_PREFIX = "[PSS] "


def compute_similarity(feat0, feat1) -> float:
    sum = 0
    for i in range(min(len(feat0), len(feat1))):
        sum += ((feat0[i] - feat1[i]) ** 2)

    return np.sqrt(2) - np.sqrt(sum)


def sim_cg(b0: str, b1: str) -> float:
    print(PSS_PREFIX + "calculating feature vector v0")
    v0: list = np.ndarray.tolist(preproc.compute_v(b0))[0]
    print(PSS_PREFIX + "v0:" + str(v0))
    print(PSS_PREFIX + "calculating feature vector v1")
    v1: list = np.ndarray.tolist(preproc.compute_v(b1))[0]
    print(PSS_PREFIX + "v1:" + str(v1))
    sim: float = compute_similarity(v0, v1)
    print(PSS_PREFIX + "simCG(p0, p1) = " + str(sim))
    return sim


def sim_cfg(b0: str, b1: str) -> float:
    print(PSS_PREFIX + "calculating feature vector w0")
    w0: list = np.ndarray.tolist(preproc.compute_w(b0))
    print(PSS_PREFIX + "w0:" + str(w0))
    print(PSS_PREFIX + "calculating feature vector w1")
    w1: list = np.ndarray.tolist(preproc.compute_w(b1))
    print(PSS_PREFIX + "w1:" + str(w1))
    sim: float = compute_similarity(w0, w1)
    print(PSS_PREFIX + "simCFG(p0, p1) = " + str(sim))
    return sim


def compare(p0: str, p1: str) -> float:
    start_time = time.time()
    (b0, b1) = projectprocessor.get_binaries(p0, p1)
    pss_value = (sim_cg(b0, b1) + sim_cfg(b0, b1)) / (2 * np.sqrt(2))
    print(PSS_PREFIX + "pss(p0, p1) = " + str(pss_value))
    print(PSS_PREFIX + "execution time (including compilation): " + str(time.time() - start_time) + " seconds")
    return pss_value


if __name__ == '__main__':
    p0 = os.path.join(DATA_PATH, "p0")
    p1 = os.path.join(DATA_PATH, "p1")
    compare(p0, p1)
