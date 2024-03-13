import os

import numpy as np

import projectprocessor
import preprocessor as preproc


def compute_similarity(feat0, feat1) -> float:
    sum = 0
    for i in range(min(len(feat0), len(feat1))):
        sum += ((feat0[i] - feat1[i]) ** 2)

    return np.sqrt(2) - np.sqrt(sum)


def sim_cg(p0: str, p1: str) -> float:
    (b0, b1) = projectprocessor.get_binaries(p0, p1)
    v0: list = np.ndarray.tolist(preproc.compute_v(b0))[0]
    v1: list = np.ndarray.tolist(preproc.compute_v(b1))[0]
    return compute_similarity(v0, v1)


def sim_cfg(p0: str, p1: str) -> float:
    (b0, b1) = projectprocessor.get_binaries(p0, p1)
    w0: list = np.ndarray.tolist(preproc.compute_w(b0))
    w1: list = np.ndarray.tolist(preproc.compute_w(b1))
    return compute_similarity(w0, w1)


def compare(p0: str, p1: str) -> float:
    pss_value = (sim_cg(p0, p1) + sim_cfg(p0, p1)) / (2 * np.sqrt(2))
    projectprocessor.clear_temporary_dirs()
    return pss_value


if __name__ == '__main__':
    path = os.getcwd()
    path += "/data/"
    p0 = path + "p0"
    p1 = path + "p1"
    print("PSS(p0, p1) = " + str(compare(p0, p1)))
