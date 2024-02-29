import os


def get_files(p0, p1):
    return search_paths(p0), search_paths(p1)


def search_paths(directory):
    paths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.c') | file.endswith('.cpp'):
                paths.append(os.path.join(root, file))
    return paths
