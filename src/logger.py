import os
import subprocess
from datetime import datetime

from src.constants import LOG_DIR, LOG_FILE, LOG_LEVEL

def log(s: str, level: int = 0, prefix: str = ""):
    if not os.path.isfile(LOG_FILE):
        try:
            write_to_file("LOG started: " + str(datetime.now()) + "\n")
        except FileNotFoundError:
            mkdir_cmd = ['mkdir', '-p', LOG_DIR]
            subprocess.run(mkdir_cmd)
            log("Created logging directory")
            log(s, level=level)
            return

    content = prefix + s + "\n"
    if level >= LOG_LEVEL.value:
        write_to_file(content)

    print(content)


def write_to_file(s: str):
    with open(LOG_FILE, "a") as file:
        file.write(s)
