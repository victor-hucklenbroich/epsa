import locale
import mimetypes
import os
import subprocess
from pathlib import Path

from demoscript import DATA_PATH
from demoscript import LOG_PREFIX


def get_binaries(p0, p1):
    clean()
    return compile_program(p0, 0), compile_program(p1, 1)


def search_paths(directory):
    paths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.c') | file.endswith('.cpp'):
                path = os.path.join(root, file)
                print(path)
                paths.append(path)

    return paths


def compile_program(dir, n: int) -> [str]:
    print(LOG_PREFIX + "compiling p" + str(n))
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

    print(LOG_PREFIX + "compiled p" + str(n) + " successfully using Makefile")
    return binaries


def compile_program_gcc(dir, n: int) -> [str]:
    files = search_paths(dir)
    binaries = []
    gcc = check_dependencies()[0]
    output_dir = os.path.join(DATA_PATH, "binaries") + str(n)
    for file in files:
        gcc_cmd = [gcc, file, '-o']
        binary = os.path.join(output_dir, Path(file).stem)
        gcc_cmd += [binary]
        mkdir_cmd = ['mkdir', '-p', output_dir]
        print(mkdir_cmd)
        subprocess.run(mkdir_cmd)
        print(gcc_cmd)
        subprocess.run(gcc_cmd)
        binaries += [binary]

    print(LOG_PREFIX + "compiled p" + str(n) + " successfully using gcc")
    return binaries


def clean():
    path = DATA_PATH
    for dirs in os.walk(path):
        for dir in dirs[1]:
            dir = os.path.join(path, dir)
            if has_makefile(dir):
                make_clean(dir)
    clear_temporary_dirs()
    print(LOG_PREFIX + "clean successful")


def make_clean(dir):
    make = check_dependencies()[1]
    make_cmd = [make, 'clean']
    subprocess.check_output(make_cmd, cwd=dir)


def clear_temporary_dirs():
    path = os.path.join(DATA_PATH, "binaries")
    for i in range(2):
        cmd = ['rm', '-rf', (path + str(i))]
        try:
            subprocess.check_output(cmd)
        except subprocess.CalledProcessError:
            continue


def decode(bytes) -> str:
    encoding = locale.getdefaultlocale()[1]
    return bytes.decode(encoding)


def has_makefile(dir) -> bool:
    makefile = os.path.join(dir, "Makefile")
    return os.path.isfile(makefile)


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
