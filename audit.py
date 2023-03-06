#!/usr/bin/env python3.7

import os
import sys
import json
from subprocess import CalledProcessError, check_call, Popen, DEVNULL, PIPE
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

# Accounts to search for things to audit.
AUDIT_ACCOUNTS = ["softdevteam", "ykjit"]

# If you want to skip any soft-dev repos, you can add them here.
SKIP_REPOS = [
    # Skipping rustc forks for now, as at the time of writing upstream rust
    # (and thus our forks) always have vulns which are out of our control.
    # Once `cargo audit` passes on upstream rust, we can reconsider these.
    ("softdevteam", "ykrustc"),
    ("softdevteam", "rustgc"),
    ("softdevteam", "alloy"),
    # unmaintained repos.
    ("softdevteam", "k2"),
    ("softdevteam", "error_recovery_experiment"),
    # externally maintained
    ("softdevteam", "WLambda"),
]

# Security advisories to skip.
# (repo-name, problem-package, rustsec-id) -> expiry-date
# Expiry date is `a datetime.date`, e.g. `date(2021, 12, 2)`.
#
# Wild cards (`*`) are allowed in the fields of the key tuple.
#
# XXX the keys of this map should also contain the account that owns the repo,
# in case different accounts contain a repo by the same name.
SKIP_ADVISORIES = {
    ("*", "chrono", "RUSTSEC-2020-0159"): date(2023, 3, 1),
    ("*", "time", "RUSTSEC-2020-0071"): date(2023, 3, 1),
    ("yk", "atty", "RUSTSEC-2021-0145"): date(2023, 6, 1),
}

UNMATCHED_SKIP_ADVISORIES = set(SKIP_ADVISORIES.keys())

# Repos which require the audit to run in a sub-dir.
# Maps a (owner, repo-name) tuple to a collection of path components suitiable
# for use with `os.path.join()`.
CUSTOM_AUDIT_DIRS = {
    ("ykjit", "ykcbf"): ["lang_tests"],
}


def should_skip_advisory(adv_tup):
    assert(len(adv_tup) == 3)

    # Look for an exact match.
    expiry = None
    if adv_tup in SKIP_ADVISORIES:
        UNMATCHED_SKIP_ADVISORIES.remove(adv_tup)
        expiry = SKIP_ADVISORIES[adv_tup]
    else:
        # Now try wildcard matching.
        for (skip_tup, skip_expiry) in SKIP_ADVISORIES.items():
            match_list = list(adv_tup)
            assert(len(skip_tup) == 3)
            for idx in range(len(skip_tup)):
                if skip_tup[idx] == '*':
                    match_list[idx] = "*"
            if tuple(match_list) == skip_tup:
                if skip_tup in UNMATCHED_SKIP_ADVISORIES:
                    UNMATCHED_SKIP_ADVISORIES.remove(skip_tup)
                expiry = skip_expiry
                break

    if expiry is None:
        return False

    _, pkg, adv_id = adv_tup
    if expiry <= date.today():
        print(f"Note: skip for {pkg}/{adv_id} has expired.")
        return False

    print(f"Note: {pkg}/{adv_id} was skipped.")
    return True


def get_sd_rust_repos(token_file):
    """Get a list of unarchived soft-dev repos written in Rust"""

    with open(token_file) as f:
        token = f.read().strip()

    gh = gh3.login(token=token)
    return [r for r in gh.repositories() if
            r.owner.login in AUDIT_ACCOUNTS and
            "Rust" in map(lambda tup: tup[0], r.languages()) and
            not r.archived and
            (r.owner.login, r.name) not in SKIP_REPOS]


def install_cargo_audit():
    check_call(["curl", "--proto", "=https", "--tlsv1.2", "-sSf",
                "https://sh.rustup.rs", "-o", "rustup.sh"])
    check_call(["sh", "rustup.sh", "--no-modify-path", "-y"])
    check_call([CARGO, "install", "cargo-audit"])


def audit(name, owner, repo):
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

    # Repos which use sub-modules (like Rust forks) need the submodules sources
    # available too.
    try:
        check_call(["git", "submodule", "update"])
    except CalledProcessError:
        return False

    try:
        dirs = CUSTOM_AUDIT_DIRS[(owner, name)]
    except KeyError:
        # No custom directories, so just audit the top-level dir.
        dirs = ["."]

    ok = True
    for audit_dir in dirs:
        # Actually do the audit.
        print(f"Running audit in {audit_dir}")
        os.chdir(audit_dir)

        # If there's no Cargo.toml, we can't audit it.
        if not os.path.exists("Cargo.toml"):
            print("No Cargo.toml. Can't audit!")
            ok = False
            continue

        # If we didn't clone afresh and `Cargo.lock` isn't tracked in git, we
        # should run `cargo update` to get the same deps as we would have with
        # a fresh clone.
        if src_exists and os.path.exists("Cargo.lock"):
            try:
                check_call(["git", "ls-files", "--error-unmatch",
                            "Cargo.lock"], stdout=DEVNULL, stderr=DEVNULL)
            except CalledProcessError:
                # `Cargo.lock` not in git.
                check_call(["cargo", "update"])

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
    problems = set()

    # First look at warnings.
    for kind in js["warnings"].values():
        for warn in kind:
            adv = warn["advisory"]
            if adv is not None:
                problems.add((repo_name, adv["package"], adv["id"]))
            else:
                # If the advisory field is None use dummy info.
                problems.add((repo_name, None, None))

    # Now look at vulnerabilities.
    for vuln in js["vulnerabilities"]["list"]:
        adv = vuln["advisory"]
        if adv is not None:
            problems.add((repo_name, adv["package"], adv["id"]))
        else:
            # If the advisory field is None use dummy info.
            problems.add((repo_name, None, None))

    for tup in problems:
        if not should_skip_advisory(tup):
            ret = False

    return ret


if __name__ == "__main__":
    try:
        token_file = sys.argv[1]
    except IndexError:
        print("usage: audit.py <token-file> [repo-name]")
        sys.exit(1)

    try:
        single_repo = sys.argv[2]
    except IndexError:
        single_repo = None

    os.environ["RUSTUP_HOME"] = RUSTUP_HOME
    os.environ["CARGO_HOME"] = CARGO_HOME

    if not os.path.exists(".cargo"):
        install_cargo_audit()

    if not os.path.exists(WORK):
        os.mkdir(WORK)

    repos = get_sd_rust_repos(token_file)

    problematic = []
    for r in repos:
        if single_repo and single_repo != r.name:
            continue
        print(f"\n\nChecking {r.clone_url}...")
        res = audit(r.name, r.owner.login, r.clone_url)
        if not res:
            problematic.append(r.name)

    if UNMATCHED_SKIP_ADVISORIES:
        print("Warning: the following advisory skips were unmatched:")
        for i in UNMATCHED_SKIP_ADVISORIES:
            print(f"  {i}")

    if problematic:
        print("\n\nThe following repos have problems:")
        for p in problematic:
            print(f"    {p}")
        sys.exit(1)
