import os
import shutil
import subprocess
import time
import zipfile
from pathlib import Path

from constants import ARCHIVE_PATH, DEMO_DATA_PATH, BASE_DATA_PATH
from src import logger, constants


def get_binaries(p0, p1):
    return compile_program(p0), compile_program(p1)


def search_dir(directory: str) -> [str]:
    paths: [str] = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.c') | file.endswith('.cpp'):
                path = os.path.join(root, file)
                paths.append(path)

    return paths


def compile_program(dir) -> str:
    logger.log("compiling " + path_tail(dir))
    start_time = time.time()
    make = constants.make()
    make_cmd = [make, 'all']
    subprocess.run(make_cmd, cwd=dir)
    logger.log("compiled " + path_tail(dir) +
               " successfully using Makefile in " + str(round(time.time() - start_time, 2)) + " seconds", level=1)
    return os.path.join(constants.TEST_PROGRAM_PATH, constants.TEST_PROGRAM)


def clean(path: Path, replace_with_archives=False):
    if replace_with_archives and zipfile.is_zipfile(ARCHIVE_PATH):
        replace_data_with_archive()
    for dirs in os.walk(path):
        for dir in dirs[1]:
            dir = os.path.join(path, dir)
            if has_makefile(dir):
                make_clean(dir)
                logger.log("removed binary and .o files in " + dir, level=1)

    logger.log("clean successful\n", level=1)


def replace_data_with_archive():
    cmd = ['rm', '-rf', DEMO_DATA_PATH]
    subprocess.check_output(cmd)
    shutil.unpack_archive(ARCHIVE_PATH, BASE_DATA_PATH)
    logger.log("replaced test data with available archives: " + ARCHIVE_PATH, level=1)


def has_makefile(dir) -> bool:
    makefile = os.path.join(dir, "Makefile")
    return os.path.isfile(makefile)


def make_clean(dir):
    make = constants.make()
    make_cmd = [make, 'clean']
    subprocess.check_output(make_cmd, cwd=dir)


def path_tail(dir: str) -> str:
    return os.path.basename(os.path.normpath(dir))
