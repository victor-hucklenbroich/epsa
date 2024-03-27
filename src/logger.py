import os
import pathlib
import subprocess
from datetime import datetime

LOG_DIR = os.path.join(os.getcwd(), 'logs')
LOG_FILE = os.path.join(LOG_DIR, datetime.now().ctime().strip() + '.log')
LOG_PREFIX: str = "[PSS] "


def log(s: str, level: int = 0):
    content = ''
    if not os.path.isfile(LOG_FILE):
        content += "LOG started: " + str(datetime.now()) + "\n"

    content += LOG_PREFIX + s
    if level >= 1:
        try:
            with open(LOG_FILE, "a") as file:
                file.write(content + "\n")
        except FileNotFoundError:
            mkdir_cmd = ['mkdir', '-p', LOG_DIR]
            subprocess.run(mkdir_cmd)
            log("Created logging directory")
            log(s, level=1)
            return

    print(content)
