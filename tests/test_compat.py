from rockhard.oscap import compatibility_warnings


def test_old_oscap_warns_for_dpkg_on_mounted_root():
    assert compatibility_warnings((1, 3, 9), ("ubuntu", "debian"), "/host")
    assert compatibility_warnings((1, 3, 9), ("debian",), "/host")


def test_no_warning_when_safe():
    assert compatibility_warnings((1, 4, 1), ("ubuntu", "debian"), "/host") == []
    assert compatibility_warnings((1, 3, 9), ("ubuntu", "debian"), "/") == []
    assert compatibility_warnings((1, 3, 9), ("rhel",), "/host") == []
