from dissect.regf import regf


def test_regf(system_hive):
    hive = regf.RegistryHive(system_hive)

    root = hive.root()
    assert len(list(root.subkeys())) == 17
    assert hive.open("Software") is root.subkey("Software") is root.subkey("software")
