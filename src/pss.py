import angr
import networkx as nx
import numpy as np
from multipledispatch import dispatch


@dispatch(str, list, list)
def compare(p0: str, v1: list, w1: list) -> float:
    feat0 = compute_features(p0)
    return compare(feat0[0], feat0[1], v1, w1)


@dispatch(list, list, list, list)
def compare(v0: list, w0: list, v1: list, w1: list) -> float:
    sim_cg: float = compute_similarity(v0, v1)
    sim_cfg: float = compute_similarity(w0, w1)
    pss: float = (sim_cg + sim_cfg) / (2 * np.sqrt(2))
    return pss


def compute_similarity(feat0: list, feat1: list) -> float:
    sum = 0
    for i in range(min(len(feat0), len(feat1))):
        sum += ((feat0[i] - feat1[i]) ** 2)
    return np.sqrt(2) - np.sqrt(sum)


def compute_features(binary: str) -> (list, list):
    proj: angr.Project = init_angr(binary)
    v = compute_v(proj)
    w = compute_w(proj)
    return v, w


@dispatch(angr.Project)
def compute_v(p: angr.Project) -> [float]:
    cg: nx.MultiGraph = construct_cg(p)
    return compute_v(cg)


@dispatch(nx.MultiGraph)
def compute_v(cg: nx.MultiGraph) -> [float]:
    spectrum = nx.laplacian_spectrum(cg, None).tolist()
    spectrum.sort(reverse=True)
    spectrum = np.array(spectrum)
    spectrum /= np.linalg.norm(spectrum)
    v: list = np.ndarray.tolist(spectrum)
    return v


@dispatch([angr.Project])
def compute_w(p: angr.Project) -> [float]:
    cfgs: [nx.DiGraph] = construct_cfgs(p)
    return compute_w(cfgs)


@dispatch(list)
def compute_w(cfgs: list) -> [float]:
    w = []
    for cfg in cfgs:
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
    proj: angr.Project = angr.Project(binary, load_options={'auto_load_libs': False})
    return proj
