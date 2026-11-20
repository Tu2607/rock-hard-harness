import pytest

from rockhard import catalog
from rockhard.osdetect import OSDetectionError, OSInfo, detect_os, parse_os_release


def make_root(tmp_path, content, rel="etc/os-release"):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return tmp_path


def test_parse_os_release_quoting():
    data = parse_os_release('ID="rhel"\nVERSION_ID=\'9.4\'\n# comment\nPRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"\nBAD LINE\n')
    assert data == {"ID": "rhel", "VERSION_ID": "9.4", "PRETTY_NAME": "Red Hat Enterprise Linux 9.4 (Plow)"}


def test_detect_reads_target_root_not_container(tmp_path):
    root = make_root(tmp_path, 'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\n')
    info = detect_os(root)
    assert (info.id, info.version_id, info.version_codename, info.id_like) == ("ubuntu", "22.04", "jammy", ("debian",))


def test_detect_falls_back_to_usr_lib(tmp_path):
    root = make_root(tmp_path, "ID=fedora\nVERSION_ID=41\n", rel="usr/lib/os-release")
    assert detect_os(root).id == "fedora"


def test_detect_missing(tmp_path):
    with pytest.raises(OSDetectionError):
        detect_os(tmp_path)


@pytest.mark.parametrize(
    "info, products, vendor, url_part",
    [
        (OSInfo("rhel", "9.4"), ("rhel9",), "redhat", "RHEL9/rhel-9.oval.xml.bz2"),
        (OSInfo("rhel", "8.10"), ("rhel8",), "redhat", "RHEL8/rhel-8.oval.xml.bz2"),
        (OSInfo("centos", "9"), ("cs9", "centos9", "rhel9"), None, None),
        (OSInfo("rocky", "9.3", ("rhel", "centos", "fedora")), ("rocky9", "rhel9"), None, None),
        (OSInfo("almalinux", "9.3"), ("almalinux9", "rhel9"), "almalinux", "alsa-9.xml.bz2"),
        (OSInfo("ol", "9.2"), ("ol9",), "oracle", "elsa-ol9.xml.bz2"),
        (OSInfo("ubuntu", "22.04", ("debian",), "jammy"), ("ubuntu2204",), "ubuntu", "com.ubuntu.jammy.usn.oval.xml.bz2"),
        (OSInfo("debian", "12", (), "bookworm"), ("debian12",), "debian", "oval-definitions-bookworm.xml.bz2"),
        (OSInfo("sles", "15.5"), ("sle15",), "suse", "suse.linux.enterprise.server.15-sp5.xml.gz"),
        (OSInfo("amzn", "2023"), ("al2023",), None, None),
        (OSInfo("myrhelclone", "9.1", ("rhel", "fedora")), ("rhel9",), None, None),
    ],
)
def test_catalog_mapping(info, products, vendor, url_part):
    assert catalog.ssg_products(info) == products
    feed = catalog.oval_feed(info)
    if vendor is None:
        assert feed is None
    else:
        assert feed.vendor == vendor and feed.url.endswith(url_part)
        assert not feed.filename.endswith((".bz2", ".gz"))


def test_unsupported_os():
    with pytest.raises(catalog.UnsupportedOSError):
        catalog.ssg_products(OSInfo("plan9", "4"))


def test_select_content_picks_first_existing_datastream(tmp_path):
    (tmp_path / "ssg-rhel9-ds.xml").write_text("<x/>")
    sel = catalog.select_content(OSInfo("rocky", "9.3"), directory=tmp_path)
    assert sel.datastream == str(tmp_path / "ssg-rhel9-ds.xml")
    assert sel.profile == catalog.STIG_PROFILE
    assert catalog.select_content(OSInfo("rhel", "9"), directory=tmp_path, profile="p").profile == "p"
