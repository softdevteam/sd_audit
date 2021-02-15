#!/usr/bin/env python3.7

import os
import sys
import json
from subprocess import CalledProcessError, check_call, Popen, PIPE
import github3 as gh3
from datetime import date

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
WORK = os.path.join(SCRIPT_DIR, "work")
CARGO_HOME = os.path.join(SCRIPT_DIR, ".cargo")
RUSTUP_HOME = os.path.join(SCRIPT_DIR, ".rustup")
CARGO = os.path.join(CARGO_HOME, "bin", "cargo")
SOFTDEV_GH = "https://github.com/softdevteam"
RUSTUP_URL = "https://sh.rustup.rs/"
GH_API_HOST = "api.github.com"
GH_API_REPOS = "/users/softdevteam/repos"

# If you want to skip any soft-dev repos, you can add them here.
SD_SKIP_REPOS = [
    # Skipping rustc forks for now, as at the time of writing upstream rust
    # (and thus our forks) always have vulns which are out of our control. Once
    # `cargo audit` passes on upstream rust, we can reconsider these.
    "ykrustc", "rustgc",
    # K2 is unmaintained.
    "k2",
]

# Security warnings to skip.
# (repo-name, package, rustsec-id) -> expiry-date
# Expiry date is `a datetime.date`.
SKIP_WARNINGS = {}

CUSTOM_AUDIT_DIRS = {
    "yk": [".", "internal_ws"],
}

# XXX Implement skipping for vulnerabilities as needed.


def get_sd_rust_repos(token_file):
    """Get a list of unarchived soft-dev repos written in Rust"""

    with open(token_file) as f:
        token = f.read().strip()

    gh = gh3.login(token=token)
    return [r for r in gh.repositories() if
            r.owner.login == "softdevteam" and
            "Rust" in map(lambda tup: tup[0], r.languages()) and
            not r.archived and
            r.name not in SD_SKIP_REPOS]


def install_cargo_audit():
    check_call(["curl", "--proto", "=https", "--tlsv1.2", "-sSf",
                "https://sh.rustup.rs", "-o", "rustup.sh"])
    check_call(["sh", "rustup.sh", "--no-modify-path", "-y"])
    check_call([CARGO, "install", "cargo-audit"])


def audit(name, repo):
    direc = os.path.join(WORK, name)

    # Either pull or update the source from git.
    src_exists = os.path.exists(direc)
    if not src_exists:
        os.chdir(WORK)
        git_cmd = ["git", "clone", repo, name]
    else:
        os.chdir(direc)
        git_cmd = ["git", "pull"]

    try:
        check_call(git_cmd)
    except CalledProcessError:
        return False

    os.chdir(direc)

    # If there's no Cargo.toml, we can't audit it.
    if not os.path.exists("Cargo.toml"):
        print("No Cargo.toml")
        return True

    # Repos which use sub-modules (like Rust forks) need the submodules sources
    # available too.
    try:
        check_call(["git", "submodule", "update"])
    except CalledProcessError:
        return False

    try:
        dirs = CUSTOM_AUDIT_DIRS[name]
    except KeyError:
        # No custom directories, so just audit the top-level dir.
        dirs = ["."]

    ok = True
    for audit_dir in dirs:
        # Actually do the audit.
        print(f"Running audit in {audit_dir}")
        os.chdir(audit_dir)

        p = Popen([CARGO, "audit", "-D", "warnings", "--json"],
                  stdout=PIPE, stderr=PIPE)
        sout, serr = p.communicate()

        try:
            js = json.loads(sout)
        except json.JSONDecodeError as e:
            print(e, file=sys.stderr)
            print(sout, file=sys.stderr)
            print(serr, file=sys.stderr)
            ok = False
            continue

        if not process_json(name, js):
            ok = False
            # Something is wrong. Print human readable output.
            try:
                check_call([CARGO, "audit", "-D", "warnings"])
            except CalledProcessError:
                continue
    return ok


def process_json(repo_name, js):
    ret = True

    # First look at warnings.
    for kind in js["warnings"].values():
        for warn in kind:
            adv = warn["advisory"]
            tup = repo_name, adv["package"], adv["id"]
            try:
                expiry = SKIP_WARNINGS[tup]
            except KeyError:
                ret = False
            else:
                del SKIP_WARNINGS[tup]
                if expiry <= date.today():
                    print(f"Note: skip for {adv['package']}/{adv['id']} "
                          "has expired.")
                    ret = False
                else:
                    print(f"Note: {adv['package']}/{adv['id']} was skipped.")

    if js["vulnerabilities"]["list"]:
        ret = False  # XXX implement skipping for vulnerabilities.

    return ret


if __name__ == "__main__":
    try:
        token_file = sys.argv[1]
    except IndexError:
        print("usage: audit.py <token-file>")
        sys.exit(1)

    os.environ["RUSTUP_HOME"] = RUSTUP_HOME
    os.environ["CARGO_HOME"] = CARGO_HOME

    if not os.path.exists(".cargo"):
        install_cargo_audit()

    if not os.path.exists(WORK):
        os.mkdir(WORK)

    repos = get_sd_rust_repos(token_file)

    problematic = []
    for r in repos:
        print(f"\n\nChecking {r.clone_url}...")
        res = audit(r.name, r.clone_url)
        if not res:
            problematic.append(r.name)

    if SKIP_WARNINGS:
        print("Warning: Unneccessarily skipped warnings:")
        for i in SKIP_WARNINGS:
            print(f"  {i}")

    if problematic:
        print("\n\nThe following repos have problems:")
        for p in problematic:
            print(f"    {p}")
        sys.exit(1)
