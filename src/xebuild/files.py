"""Finding a file whatever case its name is spelled in.

The original runs where case does not count, and the names it is handed are spelled
inconsistently -- file lists, directories a person assembled by hand, a system update's
tree -- so every mode looks things up the way it would find them.
"""

import os


def beside(directory: str, name: str) -> str | None:
    """`name` in `directory`, found whatever case it is spelled in, or None.

    The name as given first; then every entry of the directory in sorted order, so
    that of two spelled alike but for case, the same one is always taken. Release 17559
    asks for `sc_17489.bin` and what is there is `SC_17489.bin`: matching exactly loses
    54 bootloaders across the nine releases here, all of them to that and nothing else.
    """
    exact = os.path.join(directory, name)
    if os.path.isfile(exact):
        return exact
    wanted = name.lower()
    try:
        for one in sorted(os.listdir(directory)):
            if one.lower() == wanted:
                return os.path.join(directory, one)
    except OSError:
        return None
    return None
