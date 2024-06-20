import networkx as nx
from multipledispatch import dispatch

from harmonizer import harmonize
from obfuscator import obfuscate


@dispatch(str, (list, list))
def modify(p0: str, features: (list, list)):
    obfuscate(p0, features)


@dispatch(str, nx.MultiGraph, nx.DiGraph)
def modify(p0: str, cg: nx.MultiGraph, cfg: nx.DiGraph):
    harmonize(p0, cg, cfg)
