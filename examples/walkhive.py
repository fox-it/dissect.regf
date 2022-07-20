import sys

from dissect.regf import regf


def main():
    fp = open(sys.argv[1], "rb")
    hive = regf.RegistryHive(fp)

    for offset, allocated, reg_entry in hive.walk():
        if not isinstance(reg_entry, regf.KeyValue):
            continue

        if (reg_entry.kv.data_size & ~0x80000000) > 0x4000:
            print(hex(offset), "+" if allocated else "-", reg_entry.name, reg_entry.kv)


if __name__ == "__main__":
    main()
