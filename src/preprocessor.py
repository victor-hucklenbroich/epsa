import locale
import mimetypes
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import angr
import networkx as nx
import numpy as np

from constants import PROJECTS_PATH
from src import logger


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
    p.analyses.CFGEmulated()
    for function in p.kb.functions.items():
        cfgs += [function[1].transition_graph]
    return cfgs


def init_angr(binary) -> angr.Project:
    return angr.Project(binary, load_options={'auto_load_libs': False})


def get_binaries(p0, p1):
    return compile_program(p0, 0), compile_program(p1, 1)


def search_paths(directory):
    paths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.c') | file.endswith('.cpp'):
                path = os.path.join(root, file)
                logger.log("Found source: " + path)
                paths.append(path)

    return paths


def compile_program(dir, n: int) -> [str]:
    logger.log("compiling p" + str(n))
    if has_makefile(dir):
        return compile_program_cmake(dir, n)
    else:
        return compile_program_gcc(dir, n)


def compile_program_cmake(dir, n: int) -> [str]:
    binaries = []
    exclusions = ['.DS_Store', 'Makefile', 'README', '.1', '.hpp', 'c']
    make = check_dependencies()[1]
    make_cmd = [make, 'all']
    subprocess.run(make_cmd, cwd=dir)
    dir = os.path.join(dir, 'src')
    for root, dirs, files in os.walk(dir):
        for file in files:
            mime = mimetypes.guess_type(file)
            if mime[0] is None:
                file = os.path.join(dir, file)
                include: bool = True
                for exclusion in exclusions:
                    if file.endswith(exclusion):
                        include = False
                        break

                if include:
                    binaries.append(file)

    logger.log("compiled p" + str(n) + " successfully using Makefile", level=1)
    return binaries


def compile_program_gcc(dir, n: int) -> [str]:
    files = search_paths(dir)
    binaries = []
    gcc = check_dependencies()[0]
    output_dir = os.path.join(PROJECTS_PATH, "binaries") + str(n)
    for file in files:
        gcc_cmd = [gcc, file, '-o']
        binary = os.path.join(output_dir, Path(file).stem)
        gcc_cmd += [binary]
        mkdir_cmd = ['mkdir', '-p', output_dir]
        logger.log(mkdir_cmd)
        subprocess.run(mkdir_cmd)
        logger.log(gcc_cmd)
        subprocess.run(gcc_cmd)
        binaries += [binary]

    logger.log("compiled p" + str(n) + " successfully using gcc", level=1)
    return binaries


def clean(replace_with_archives=False):
    path = PROJECTS_PATH
    if replace_with_archives and has_archive(path):
        replace_data_with_archive(path)
        logger.log("replaced test data with available archives", level=1)
    for dirs in os.walk(path):
        for dir in dirs[1]:
            dir = os.path.join(path, dir)
            if has_makefile(dir):
                make_clean(dir)
    clear_temporary_dirs()
    logger.log("clean successful", level=1)


def has_archive(data_path) -> bool:
    data_archive = data_path + ".zip"
    return zipfile.is_zipfile(data_archive)


def replace_data_with_archive(data_path):
    cmd = ['rm', '-rf', data_path]
    subprocess.check_output(cmd)
    data_archive = data_path + ".zip"
    shutil.unpack_archive(data_archive, data_path)


def has_makefile(dir) -> bool:
    makefile = os.path.join(dir, "Makefile")
    return os.path.isfile(makefile)


def make_clean(dir):
    make = check_dependencies()[1]
    make_cmd = [make, 'clean']
    subprocess.check_output(make_cmd, cwd=dir)


def clear_temporary_dirs():
    path = os.path.join(PROJECTS_PATH, "binaries")
    for i in range(2):
        cmd = ['rm', '-rf', (path + str(i))]
        try:
            subprocess.check_output(cmd)
        except subprocess.CalledProcessError:
            continue


def decode(bytes) -> str:
    encoding = locale.getdefaultlocale()[1]
    return bytes.decode(encoding)


def check_dependencies():
    required = ['gcc', 'make']

    dependencies = []
    for dependency in required:
        path = decode(subprocess.check_output(['which', dependency]))

        if path.find(dependency) < 0:
            raise Exception(dependency + ' not found in $PATH.')
        else:
            dependencies += [path.replace('\n', '')]

    return dependencies
