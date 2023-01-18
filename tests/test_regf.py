from dissect.regf import regf


def test_regf(system_hive):
    hive = regf.RegistryHive(system_hive)

    root = hive.root()
    assert len(list(root.subkeys())) == 17
    assert hive.open("Software") is root.subkey("Software") is root.subkey("software")

    lsa = hive.open("ControlSet001\\Control\\LSA")
    assert lsa.subkey("JD").class_name == "cdebfed5"
    assert lsa.subkey("Skew1").class_name == "7db4e11c"
    assert lsa.subkey("GBG").class_name == "b185f3f2"
    assert lsa.subkey("Data").class_name == "a282942c"

    assert hive.open("ControlSet001\\Services\\Tcpip\\Parameters\\DNSRegisteredAdapters").class_name == "DynDRootClass"
