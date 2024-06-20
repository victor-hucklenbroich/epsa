import networkx as nx
import pss


def harmonize(p0: str, graphs: (nx.MultiGraph, [nx.DiGraph])):
    cg0: nx.MultiGraph = pss.construct_cg(pss.init_angr(p0))
    cg1: nx.MultiGraph = graphs[0]
    cfgs1: [nx.DiGraph] = graphs[1]
    res = nx.graph_edit_distance(cg0, cg1)
    pass
