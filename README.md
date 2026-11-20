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
| AlmaLinux / Rocky | `almalinux{N}` / `rocky{N}`, falls back to `rhel{N}`* | no | AlmaLinux (Rocky: none yet) |
| CentOS / Stream | `centos{N}` / `cs{N}` | no | RHEL feed (7/8, advisory) |
| Ubuntu | `ubuntu{XXYY}` | 20.04, 22.04 (recent SSG) | Canonical CVE OVAL |
| Debian | `debian{N}` | no (pass `--profile`) | Debian |
| SLES 12/15 | `sle{N}` | yes | SUSE |
| Fedora, openSUSE, Amazon Linux | `fedora`, `opensuse`, `al{N}` | no | openSUSE Leap only |

\* RHEL content checks for `redhat-release`, so on a rebuild most rules come back `notapplicable`. Treat the fallback as a placeholder.

If the host has no STIG profile, `scan compliance` fails and lists the profiles that are available; choose one with `--profile`.

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
| `remediation/scripts/*.sh` | One script per automatable failed rule, from SSG's own fixes. Not executable until reviewed |
| `remediation/plan.json` | Which rules got scripts, which need Claude (`manual`), which need a human look (`review`) |
| `cve-oval-results.xml`, `cve-report.html` | Raw OVAL results and report |
| `cve-findings.json` | True vulnerability/patch definitions: CVEs, vendor severity, advisories, and the criteria that matched (affected package and fixed version) |

## Development

```bash
pip install -e '.[test]'
pytest
```

Test fixtures in `tests/fixtures/` are real `oscap` output: a trimmed STIG ARF from an Ubuntu 20.04 target and OVAL results from a hand-written feed that mimics Red Hat, Ubuntu and Debian metadata.

## Known limitations

* Probes that query a running service (systemd, D-Bus) see the container, not the host. Rules that depend on them may report `notchecked` or `error`; these land in the `review` bucket.
* OpenSCAP is part of the container image, not the Python package, because `oscap` is a C binary with its own libraries and probes. The image refuses to build with OpenSCAP older than 1.4.0; pin an exact version with `--build-arg OPENSCAP_VERSION=...`.
* OpenSCAP 1.3.9 (Ubuntu 24.04's package) crashes in the `dpkginfo` probe when scanning a mounted root. `rockhard detect` reports the `oscap` version and warns about this. The image uses Fedora's OpenSCAP 1.4.x; Debian and Ubuntu targets still need verification on a real host.
