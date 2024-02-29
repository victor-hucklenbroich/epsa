import numpy as np
import os

import classloader as cl
import preprocessor as preproc

import test


def compute_similarity(feat0, feat1) -> float:
    sum = 0
    for i in range(min(len(feat0), len(feat1))):
        sum += ((feat0[i] - feat1[i]) ** 2)

    return np.sqrt(2) - np.sqrt(sum)


def sim_cg(p0, p1) -> float:
    (f0, f1) = cl.get_files(p0, p1)
    v0 = preproc.compute_v(f0)
    v1 = preproc.compute_v(f1)
    return compute_similarity(v0, v1)


def sim_cfg(p0, p1) -> float:
    (f0, f1) = cl.get_files(p0, p1)
    w0 = preproc.compute_w(f0)
    w1 = preproc.compute_w(f1)
    return compute_similarity(w0, w1)


def pss(p0, p1) -> float:
    return (sim_cg(p0, p1) + sim_cfg(p0, p1)) / (2 * np.sqrt(2))


def main():
    path = os.getcwd()
    path += "/data/"
    p0 = path + "p0"
    p1 = path + "p1"
    print("PSS(p0, p1) = " + str(pss(p0, p1)))


if __name__ == '__main__':
    main()
