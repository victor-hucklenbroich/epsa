import locale
import os.path
import re
import subprocess
from pathlib import Path

import angr
import networkx as nx
import numpy as np


def compute_v(files) -> [float]:
    cg_graphs = []
    for file in files:
        cflow = call_cflow(file)
        cg_graphs += [construct_cg(cflow).to_undirected(False, False)]

    v = []
    for cg in cg_graphs:
        v += [nx.laplacian_spectrum(cg, None)]

    v /= np.linalg.norm(v)
    return v


def compute_w(files, n: int) -> [float]:
    cfg_graphs = []
    binaries = compile_program(files, n)
    for binary in binaries:
        cfg_graphs += [construct_cfg(binary)]

    clear_temporary_dirs()

    w = []
    for cfg in cfg_graphs:
        w += [nx.number_of_edges(cfg)]

    w /= np.linalg.norm(w)
    return w


def construct_cg(cflow_str) -> nx.DiGraph:
    lines = cflow_str.replace('\r', '').split('\n')

    g = nx.DiGraph()
    stack = dict()
    for line in lines:
        if line == '':
            continue

        src_line_no = re.findall(':.*>', line)
        if src_line_no:
            src_line_no = int(src_line_no[0][1:-1])
        else:
            src_line_no = -1

        s = re.sub(r'\(.*$', '', line)
        s = re.sub(r'^\{\s*', '', s)
        s = re.sub(r'}\s*', r'\t', s)

        (nest_level, func_name) = re.split(r'\t', s)
        nest_level = int(nest_level)
        cur_node = func_name

        stack[nest_level] = cur_node

        if cur_node not in g:
            g.add_node(cur_node, nest_level=nest_level, src_line=src_line_no)

        if nest_level != 0:
            pre_node = stack[nest_level - 1]

            if g.has_edge(pre_node, cur_node):
                continue

            g.add_edge(pre_node, cur_node)

    return g


def construct_cfg(binary) -> nx.DiGraph:
    p = angr.Project(binary, load_options={'auto_load_libs': False})
    cfg = p.analyses.CFGFast()
    return cfg.graph


def call_cflow(file) -> str:
    cflow = check_dependencies()[0]
    cflow_cmd = [cflow]
    cflow_cmd += ['-l']
    cflow_cmd += [file]

    cflow_data = decode(subprocess.check_output(cflow_cmd))
    return cflow_data


def compile_program(files, n: int) -> [str]:
    binaries = []
    gcc = check_dependencies()[1]
    output_dir = os.path.join("data", "binaries") + str(n)
    for file in files:
        gcc_cmd = [gcc, file, '-o']
        binary = os.path.join(output_dir, Path(file).stem)
        gcc_cmd += [binary]
        mkdir_cmd = ['mkdir', '-p', output_dir]
        subprocess.run(mkdir_cmd)
        subprocess.run(gcc_cmd)
        binaries += [binary]

    return binaries


def clear_temporary_dirs():
    path = os.path.join("data", "binaries")
    for i in range(2):
        cmd = ['rm', '-rf', (path + str(i))]
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError:
            continue


def decode(bytes) -> str:
    encoding = locale.getdefaultlocale()[1]
    return bytes.decode(encoding)


def check_dependencies():
    required = ['cflow', 'gcc']

    dependencies = []
    for dependency in required:
        path = decode(subprocess.check_output(['which', dependency]))

        if path.find(dependency) < 0:
            raise Exception(dependency + ' not found in $PATH.')
        else:
            dependencies += [path.replace('\n', '')]

    return dependencies
