import time

import angr
import networkx as nx
import numpy as np

import preprocessor as preproc
from src import logger


def compare(p0: str, p1: str) -> float:
    start_time = time.time()
    (b0, b1) = preproc.get_binaries(p0, p1)
    pss_value = (sim_cg(b0, b1) + sim_cfg(b0, b1)) / (2 * np.sqrt(2))
    logger.log("pss(p0, p1) = " + str(pss_value), level=1)
    logger.log("pss execution time (including compilation): " + str(round(time.time() - start_time, 2)) + " seconds\n",
               level=1)
    return pss_value


def sim_cg(b0: str, b1: str) -> float:
    logger.log("calculating feature vector v0")
    v0: list = compute_v(b0)[0]
    logger.log("v0: " + str(v0[:10]), level=1)
    logger.log("calculating feature vector v1")
    v1: list = compute_v(b1)[0]
    logger.log("v1: " + str(v1[:10]), level=1)
    sim: float = compute_similarity(v0, v1)
    logger.log("simCG(p0, p1) = " + str(sim), level=1)
    return sim


def sim_cfg(b0: str, b1: str) -> float:
    logger.log("calculating feature vector w0")
    w0: list = np.ndarray.tolist(compute_w(b0))
    logger.log("w0: " + str(w0[:5]), level=1)
    logger.log("calculating feature vector w1")
    w1: list = np.ndarray.tolist(compute_w(b1))
    logger.log("w1: " + str(w1[:5]), level=1)
    sim: float = compute_similarity(w0, w1)
    logger.log("simCFG(p0, p1) = " + str(sim), level=1)
    return sim


def compute_similarity(feat0, feat1) -> float:
    sum = 0
    for i in range(min(len(feat0), len(feat1))):
        sum += ((feat0[i] - feat1[i]) ** 2)

    return np.sqrt(2) - np.sqrt(sum)


def compute_v(binaries) -> [float]:
    cg_graphs = []
    for binary in binaries:
        cg_graphs += [construct_cg(binary)]

    v = []
    for cg in cg_graphs:
        spectrum = nx.laplacian_spectrum(cg, None).tolist()
        spectrum.sort(reverse=True)
        spectrum = np.array(spectrum)
        spectrum /= np.linalg.norm(spectrum)
        v += [spectrum]

    return v


def compute_w(binaries) -> [float]:
    cfg_graphs = []
    for binary in binaries:
        cfg_graphs.extend(construct_cfgs(binary))

    w = []
    for cfg in cfg_graphs:
        w += [nx.number_of_edges(cfg)]

    w.sort(reverse=True)
    w /= np.linalg.norm(w)
    return w


def construct_cg(binary) -> nx.MultiGraph:
    cfg = init_angr(binary).analyses.CFG(show_progressbar=True)
    return cfg.functions.callgraph.to_undirected()


def construct_cfgs(binary) -> [nx.DiGraph]:
    cfgs = []
    p = init_angr(binary)
    p.analyses.CFGEmulated(show_progressbar=True)
    for function in p.kb.functions.items():
        cfgs += [function[1].transition_graph]
    return cfgs


def init_angr(binary) -> angr.Project:
    start_time = time.time()
    proj: angr.Project = angr.Project(binary, load_options={'auto_load_libs': False})
    logger.log("initialised angr: " + str(proj) + " in " + str(round(time.time() - start_time, 2)) + " seconds")
    return proj
