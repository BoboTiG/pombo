# coding: utf-8
"""Pombo - bump the version everywhere."""
# pylint: disable=invalid-name

import sys


FILES = (
    (
        "windows/create-package.iss",
        "#define MyAppVersion",
        '#define MyAppVersion "{version}"\n',
    ),
    ("pombo.py", "__version__ = ", '__version__ = "{version}"\n'),
    ("VERSION", "", "{version}\n"),
)


def main(version):
    # type: (str) -> int
    """Entry point."""

    for file, pattern, replacement in FILES:
        with open(file, encoding="utf-8") as ifile:
            contents = ifile.readlines()

        for idx, line in enumerate(contents):
            if line.startswith(pattern):
                contents[idx] = replacement.format(version=version)
                break

        with open(file, "w", encoding="utf-8") as ofile:
            ofile.writelines(contents)

        print(">>> Updated", file)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
