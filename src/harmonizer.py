import pathlib

import networkx as nx

import constants
import logger
import preprocessor as preproc


def harmonize(p0: str, p1: str):
    (cg0, cg1) = construct_graphs(p0, p1)
    pass


def construct_graphs(p0: str, p1: str) -> (nx.MultiGraph, nx.MultiGraph):
    try:
        cg0: nx.MultiGraph = preproc.construct_cg(preproc.find_binaries(p0)[0])
        logger.log("CG(p0) = " + str(cg0), level=1, prefix=constants.LOG_PREFIX_MOD)
        cg1: nx.MultiGraph = preproc.construct_cg(preproc.find_binaries(p1)[0])
        logger.log("CG(p1) = " + str(cg1), level=1, prefix=constants.LOG_PREFIX_MOD)
        return cg0, cg1
    except Exception:
        logger.log(
            "Error occurred during call graph construction: " + str(
                Exception) + "; cleaning and recompiling before trying again...",
            prefix=constants.LOG_PREFIX_MOD)
        preproc.clean(pathlib.Path(p0).parent.absolute())
        preproc.get_binaries(p0, p1)
        return construct_graphs(p0, p1)
