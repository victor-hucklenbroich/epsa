import time

import angr
import networkx as nx
import numpy as np

import preprocessor as preproc
from src import logger


def compare(p0: str, p1: str) -> float:
    start_time = time.time()
    (b0, b1) = preproc.get_binaries(p0, p1)
    proj0: angr.Project = init_angr(b0[0])
    proj1: angr.Project = init_angr(b1[0])
    pss_value = (sim_cg(proj0, proj1) + sim_cfg(proj0, proj1)) / (2 * np.sqrt(2))
    logger.log("pss(p0, p1) = " + str(pss_value), level=1)
    logger.log("pss execution time (including compilation): " + str(round(time.time() - start_time, 2)) + " seconds\n",
               level=1)
    return pss_value


def sim_cg(p0: angr.Project, p1: angr.Project) -> float:
    logger.log("calculating feature vector v0")
    v0: list = compute_v(p0)
    logger.log("v0: " + str(v0[:10]), level=1)
    logger.log("calculating feature vector v1")
    v1: list = compute_v(p1)
    logger.log("v1: " + str(v1[:10]), level=1)
    sim: float = compute_similarity(v0, v1)
    logger.log("simCG(p0, p1) = " + str(sim), level=1)
    return sim


def sim_cfg(p0: angr.Project, p1: angr.Project) -> float:
    logger.log("calculating feature vector w0")
    w0: list = (compute_w(p0))
    logger.log("w0: " + str(w0[:5]), level=1)
    logger.log("calculating feature vector w1")
    w1: list = (compute_w(p1))
    logger.log("w1: " + str(w1[:5]), level=1)
    sim: float = compute_similarity(w0, w1)
    logger.log("simCFG(p0, p1) = " + str(sim), level=1)
    return sim


def compute_similarity(feat0: list, feat1: list) -> float:
    sum = 0
    for i in range(min(len(feat0), len(feat1))):
        sum += ((feat0[i] - feat1[i]) ** 2)

    return np.sqrt(2) - np.sqrt(sum)


def compute_features(p: str) -> (list, list):
    proj = init_angr(preproc.compile_program(p)[0])
    v = compute_v(proj)
    w = compute_w(proj)
    return v, w


def compute_v(p: angr.Project) -> [float]:
    cg_graphs = [construct_cg(p)]
    v = []
    for cg in cg_graphs:
        spectrum = nx.laplacian_spectrum(cg, None).tolist()
        spectrum.sort(reverse=True)
        spectrum = np.array(spectrum)
        spectrum /= np.linalg.norm(spectrum)
        v += [spectrum]

    return np.ndarray.tolist(v[0])


def compute_w(p: angr.Project) -> [float]:
    cfg_graphs = []
    cfg_graphs.extend(construct_cfgs(p))
    w = []
    for cfg in cfg_graphs:
        w += [nx.number_of_edges(cfg)]

    w.sort(reverse=True)
    w /= np.linalg.norm(w)
    return np.ndarray.tolist(w)


def construct_cg(p: angr.Project) -> nx.MultiGraph:
    cfg = p.analyses.CFG(show_progressbar=True)
    return cfg.functions.callgraph.to_undirected()


def construct_cfgs(p: angr.Project) -> [nx.DiGraph]:
    cfgs = []
    p.analyses.CFGFast(show_progressbar=True)
    for function in p.kb.functions.items():
        cfgs += [function[1].transition_graph]
    return cfgs


def init_angr(binary: str) -> angr.Project:
    start_time = time.time()
    proj: angr.Project = angr.Project(binary, load_options={'auto_load_libs': False})
    logger.log("initialised angr: " + str(proj) + " in " + str(round(time.time() - start_time, 2)) + " seconds")
    return proj


def compare_with_given_features(v0: list, w0: list, v1: list, w1: list) -> float:
    logger.log("v0: " + str(v0[:10]), level=1)
    logger.log("v1: " + str(v1[:10]), level=1)
    scg: float = compute_similarity(v0, v1)
    logger.log("simCG(p0, p1) = " + str(scg), level=1)
    logger.log("w0: " + str(w0[:5]), level=1)
    logger.log("w1: " + str(w1[:5]), level=1)
    scfg: float = compute_similarity(w0, w1)
    logger.log("simCFG(p0, p1) = " + str(scfg), level=1)
    pss_value: float = (scg + scfg) / (2 * np.sqrt(2))
    logger.log("pss(p0, p1) = " + str(pss_value), level=1)
    return pss_value


def calculate_from_optimized(md: float) -> float:
    return (2 * np.sqrt(2) - md) / (2 * np.sqrt(2))
