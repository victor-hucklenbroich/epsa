import locale
import os
import subprocess
from pathlib import Path


def get_binaries(p0, p1):
    return compile_program(search_paths(p0), 0), compile_program(search_paths(p1), 1)


def search_paths(directory):
    paths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.c') | file.endswith('.cpp'):
                paths.append(os.path.join(root, file))
    return paths


def compile_program(files, n: int) -> [str]:
    binaries = []
    gcc = check_dependencies()[0]
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
    required = ['gcc']

    dependencies = []
    for dependency in required:
        path = decode(subprocess.check_output(['which', dependency]))

        if path.find(dependency) < 0:
            raise Exception(dependency + ' not found in $PATH.')
        else:
            dependencies += [path.replace('\n', '')]

    return dependencies
