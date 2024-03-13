import angr
import networkx as nx
import numpy as np


def compute_v(binaries) -> [float]:
    cg_graphs = []
    for binary in binaries:
        cg_graphs += [construct_cg(binary)]

    v = []
    for cg in cg_graphs:
        v += [nx.laplacian_spectrum(cg, None)]

    v /= np.linalg.norm(v)
    return v


def compute_w(binaries) -> [float]:
    cfg_graphs = []
    for binary in binaries:
        cfg_graphs.extend(construct_cfgs(binary))

    w = []
    for cfg in cfg_graphs:
        w += [nx.number_of_edges(cfg)]

    w /= np.linalg.norm(w)
    return w


def construct_cg(binary) -> nx.MultiGraph:
    cfg = init_angr(binary).analyses.CFG(show_progressbar=True)
    return cfg.functions.callgraph.to_undirected()


def construct_cfgs(binary) -> [nx.DiGraph]:
    cfgs = []
    p = init_angr(binary)
    p.analyses.CFGEmulated()
    for function in p.kb.functions.items():
        cfgs += [function[1].transition_graph]
    return cfgs


def init_angr(binary) -> angr.Project:
    return angr.Project(binary, load_options={'auto_load_libs': False})
