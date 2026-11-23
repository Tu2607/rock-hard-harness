# rock-hard-harness

*Get your system hard.*

A harness that lets Claude scan a Linux host with [OpenSCAP](https://www.open-scap.org/) and act on the results, on two tracks that share one engine:

| Track | Scan | What Claude does with it |
|---|---|---|
| **Compliance** | DISA STIG profile from SCAP Security Guide (`oscap xccdf eval`) | Reviews failed rules, ships one remediation script per automatable rule, writes fixes for the rules SSG can't automate |
| **CVE** | Vendor OVAL feed (`oscap oval eval`) | Triage (CISA KEV, EPSS), patch or mitigation suggestions, reachability checks |

Remediation scripts are generated **for review only**. Nothing in the harness executes them.

## How it works

```
host /  ──(read-only bind)──▶  /host in the scanner container
                                  │
              rockhard detect     │  reads /host/etc/os-release → picks SSG datastream,
                                  │  STIG profile and vendor OVAL feed
              rockhard scan ...   │  oscap with OSCAP_PROBE_ROOT=/host (oscap-chroot style)
                                  ▼
                        /out  (ARF / OVAL results, HTML reports,
                               normalised findings JSON, remediation scripts)
```

* **One engine.** Both tracks run `oscap` against the mounted host root and feed a shared parser layer (`rockhard.parsers`) that emits normalised JSON.
* **Isolation.** The container gets the host root read-only, drops every capability except `DAC_READ_SEARCH` (read root-only files) and `SYS_CHROOT` (oscap's probes chroot into the mounted root), runs with `no-new-privileges`, a read-only image filesystem and **no network** during scans. Only `feeds fetch` has network access.
* **Every command prints JSON**, so Claude can drive the harness through a shell today. An MCP server over the same library is planned.

## Supported targets

Detection and content mapping live in [`src/rockhard/catalog.py`](src/rockhard/catalog.py).

| OS | SSG datastream | STIG profile in SSG | OVAL feed |
|---|---|---|---|
| RHEL 7/8/9 | `rhel{N}` | yes | Red Hat |
| Oracle Linux | `ol{N}` | 7, 8, 9 | Oracle ELSA |
| AlmaLinux / Rocky | `almalinux{N}` / `rocky{N}`, falls back to `rhel{N}`* | no (Alma: CIS, ANSSI, ...) | AlmaLinux (Rocky: none yet) |
| CentOS / Stream | `centos{N}` / `cs{N}` | no | RHEL feed (7/8, advisory) |
| Ubuntu | `ubuntu{XXYY}` | 22.04, 24.04 (SSG 0.1.82; 20.04 needs `SSG_VERSION=0.1.76`) | Canonical USN OVAL (fixed CVEs)† |
| Debian | `debian{N}` | no (pass `--profile`) | Debian |
| SLES 12/15 | `sle{N}` | yes | SUSE |
| Fedora, openSUSE, Amazon Linux | `fedora`, `opensuse`, `al{N}` | no | openSUSE Leap only |

† Canonical's full CVE OVAL (unfixed CVEs too) is ~350 MB for jammy and oscap needs more than 4 GB of RAM for it. Fetch it with `feeds fetch --url https://security-metadata.canonical.com/oval/com.ubuntu.<codename>.cve.oval.xml.bz2` and pass it with `scan cve --feed`.

\* RHEL content checks for `redhat-release`, so on a rebuild every rule comes back `notapplicable` (verified on Rocky 9). `scan compliance` warns when nothing was evaluated.

macOS and Windows are not supported: SCAP Security Guide has no STIG content for them and OpenSCAP has no maintained build there.

If the host has no STIG profile, `scan compliance` fails and lists the profiles that are available; choose one with `--profile`.

## Verified targets

Scan, then every generated script applied in a chroot of the target, then a rescan (SSG 0.1.82, OpenSCAP 1.4.x, 2026-11-20). Targets were distro images with a kernel, sshd, auditd, chrony, grub and rsyslog installed, not booted machines, so fixes that need a running systemd, a real bootloader or a live kernel (`sysctl -w`, `grubby`, `systemctl`) could not take effect.

| Target | Profile | Failed before | Scripts | Rules fixed by their script | Left over |
|---|---|---|---|---|---|
| Ubuntu 22.04 | STIG | 140 | 134 | 129 | runtime sysctl, ctrl-alt-del (systemd) |
| Ubuntu 24.04 | STIG | 142 | 135 | 128 | same, plus `/var/log` perms, chrony server |
| Oracle Linux 9 | STIG | 256 | 238 | 169 | PAM/pwquality (image's PAM not managed by authselect), runtime sysctl, grub args, crypto policy, FIPS |
| Oracle Linux 8 | STIG | 229 | 213 | 148 | same |
| RHEL 9 (UBI) | STIG | 17 | 10 | scan only | |
| AlmaLinux 9 | CIS server L1 | 10 | 7 | scan only | |
| Debian 12 | CIS level 1 server | 15 | 11 | scan only | |
| Amazon Linux 2023 | CIS server L1 | 8 | 5 | scan only | |
| openSUSE Leap 15.6 | standard | 0 | 0 | scan only | profile has 3 rules |
| Rocky 9 | STIG (RHEL fallback) | n/a | n/a | n/a | nothing applies; warning raised |

Ubuntu 22.04 was also verified on a booted VM (58 of 67 scripted rules fixed). SLES has STIG content but no image could be fetched for testing.

## Quick start (container)

```bash
sudo bin/rockhard-container build
sudo bin/rockhard-container detect
sudo bin/rockhard-container scan compliance --remediate
sudo bin/rockhard-container feeds fetch
sudo bin/rockhard-container scan cve
ls rockhard-out/
```

Rootful podman or docker is required: a rootless container cannot read root-owned host files.

## Without a container

```bash
pip install -e '.[test]'          # needs oscap and SSG content installed on the machine
rockhard detect --root /
rockhard scan compliance --root /mnt/target --out ./out --remediate
rockhard parse compliance out/compliance-arf.xml
rockhard parse cve out/cve-oval-results.xml
```

## Outputs

| File | Contents |
|---|---|
| `compliance-arf.xml`, `compliance-report.html` | Raw OpenSCAP results and report |
| `compliance-findings.json` | Non-passing rules: result, severity, STIG/SRG/CCI ids, category (`automatable`, `manual`, `review`), description |
| `remediation/scripts/*.sh` | One script per automatable failed rule, from SSG's own fixes, named `NNN_<severity>_<rule>.sh`. `NNN` is the run order SSG uses (package installs before the rules that configure them). Not executable until reviewed |
| `remediation/plan.json` | Which rules got scripts, which need Claude (`manual`), which need a human look (`review`) |
| `cve-oval-results.xml`, `cve-report.html` | Raw OVAL results and report |
| `cve-findings.json` | True vulnerability/patch definitions: CVEs, vendor severity, advisories, and the criteria that matched (affected package and fixed version) |

## Development

```bash
pip install -e '.[test]'
pytest
```

Test fixtures in `tests/fixtures/` are real `oscap` output: a trimmed STIG ARF from an Ubuntu 20.04 target, generated fixes from OpenSCAP 1.3.9 and 1.4.2, and OVAL results from a hand-written feed that mimics Red Hat, Ubuntu and Debian metadata.

## Known limitations

* Runtime state is read from the host, not the container. oscap's probes chroot into `/host`, so the systemd probes talk to the host's systemd over `/host/run/dbus/system_bus_socket` (connecting to a socket works through a read-only mount), and sysctl and process checks read the host's `/proc`. Verified against a booted Ubuntu 22.04 with every capability but `DAC_READ_SEARCH`/`SYS_CHROOT` dropped and no network: service rules matched `systemctl` (including a service masked mid-test). This needs the host's `/run` inside the mount, which `rockhard-container` does; scanning an offline image or disk leaves those rules `unknown`.
* Rules SSG cannot check automatically come back `notchecked` on any host (e.g. `only_allow_dod_certs`, `account_temp_expire_date`); they land in the `review` bucket. Probes with no chroot support (`uname`, `interface`, `inetlisteningservers`) do not run; on the STIG profiles that affects kernel CVE definitions and a handful of RHEL network rules.
* OpenSCAP is part of the container image, not the Python package, because `oscap` is a C binary with its own libraries and probes. The image refuses to build with OpenSCAP older than 1.4.0; pin an exact version with `--build-arg OPENSCAP_VERSION=...`.
* OpenSCAP 1.3.9 (Ubuntu 24.04's package) crashes in the `dpkginfo` probe when scanning a mounted root. `rockhard detect` reports the `oscap` version and warns about this. The image uses Fedora's OpenSCAP 1.4.x, which has been verified against an Ubuntu 22.04 host (STIG and USN scans).
* OVAL `uname` tests do not run against a mounted root, so kernel advisories come back `unknown` and are left out of `cve-findings.json` (614 of them on Ubuntu 22.04). `scan cve` reports the `unknown` count in `counts` and `warnings`; check the host's running kernel separately.
* With Docker, or podman older than 4 (e.g. Ubuntu 22.04's 3.4.4), there is no usable recursive read-only bind of `/` (Docker requires `rprivate` propagation for one and refuses it for a source that contains `/var/lib/docker`). `rockhard-container` then binds every host mount point read-only one by one; the engine's own storage (`/var/lib/containers/storage/overlay` or `/var/lib/docker`) stays writable in that mode. Prefer podman 4+.
* OpenSCAP reads the rpm database from `/usr/lib/sysimage/rpm` whenever that directory exists. EL8/EL9 hosts keep theirs in `/var/lib/rpm`, and some (Oracle Linux 9) also have a stale `/usr/lib/sysimage/rpm`, which made every rule `notapplicable`. `rockhard-container` binds `/var/lib/rpm` over it inside the container, and `detect`/`scan` warn when running without the wrapper.
* The image needs an OpenSCAP build with both the `rpminfo` and `dpkginfo` probes; the build checks this. EL10's OpenSCAP has no `dpkginfo`, so an EL-based image scans Debian/Ubuntu as all `notapplicable`.
