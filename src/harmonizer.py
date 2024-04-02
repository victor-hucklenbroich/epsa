import networkx as nx

import preprocessor as preproc


def harmonize(p0: str, p1: str):
    (cg0, cg1) = construct_graphs(p0, p1)
    pass


def construct_graphs(p0: str, p1: str) -> (nx.MultiGraph, nx.MultiGraph):
    try:
        cg0: nx.MultiGraph = preproc.construct_cg(preproc.find_binaries(p0)[0])
        cg1: nx.MultiGraph = preproc.construct_cg(preproc.find_binaries(p1)[0])
        return cg0, cg1
    except Exception:
        print("EXCEPTION CLAUSE")
        preproc.clean()
        preproc.get_binaries(p0, p1)
        return construct_graphs(p0, p1)
