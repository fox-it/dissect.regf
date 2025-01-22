import sys
from pathlib import Path

from dissect.regf import regf


def main() -> None:
    with Path(sys.argv[1]).open("rb") as fh:
        hive = regf.RegistryHive(fh)

        for offset, allocated, cell in hive.walk():
            if not isinstance(cell, regf.KeyValue):
                continue

            if cell.size > 0x4000:
                print(hex(offset), "+" if allocated else "-", cell.name, cell.cell)


if __name__ == "__main__":
    main()
