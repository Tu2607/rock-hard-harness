from rockhard.oscap import compatibility_warnings


def test_old_oscap_warns_for_dpkg_on_mounted_root():
    assert compatibility_warnings((1, 3, 9), ("ubuntu", "debian"), "/host")
    assert compatibility_warnings((1, 3, 9), ("debian",), "/host")


def test_no_warning_when_safe():
    assert compatibility_warnings((1, 4, 1), ("ubuntu", "debian"), "/host") == []
    assert compatibility_warnings((1, 3, 9), ("ubuntu", "debian"), "/") == []
    assert compatibility_warnings((1, 3, 9), ("rhel",), "/host") == []


def _el_root(tmp_path, dbpath="%{_var}/lib/rpm", sysimage=True):
    from pathlib import Path

    (tmp_path / "usr/lib/rpm").mkdir(parents=True)
    (tmp_path / "usr/lib/rpm/macros").write_text(f"%_dbpath\t\t{dbpath}\n%_dbpath_rebuild\t%{{_dbpath}}\n")
    (tmp_path / "var/lib/rpm").mkdir(parents=True)
    if sysimage:
        (tmp_path / "usr/lib/sysimage/rpm").mkdir(parents=True)
    return Path(tmp_path)


def test_rpmdb_shadowed_on_el9_with_stale_sysimage(tmp_path):
    from rockhard.oscap import rpmdb_shadowed

    root = _el_root(tmp_path)
    assert rpmdb_shadowed(root)
    assert any("rpm database" in w for w in compatibility_warnings((1, 4, 4), ("ol", "fedora"), root))


def test_rpmdb_not_shadowed(tmp_path):
    from rockhard.oscap import rpmdb_shadowed

    assert not rpmdb_shadowed(_el_root(tmp_path / "a", sysimage=False))  # plain EL9
    assert not rpmdb_shadowed(_el_root(tmp_path / "b", dbpath="%{_usr}/lib/sysimage/rpm"))  # Fedora/EL10
    root = tmp_path / "c"
    (root / "usr/lib/sysimage/rpm").mkdir(parents=True)
    (root / "var/lib").mkdir(parents=True)
    (root / "var/lib/rpm").symlink_to("../../usr/lib/sysimage/rpm")
    assert not rpmdb_shadowed(root)


def test_applicability_warning():
    from rockhard.oscap import applicability_warning

    assert applicability_warning({"notselected": 1063, "notapplicable": 477}, "/x/ssg-rhel9-ds.xml", "Rocky Linux 9")
    assert applicability_warning({"notapplicable": 10, "pass": 1}, "ssg-rhel9-ds.xml", "RHEL 9") is None
