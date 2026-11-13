#!/usr/bin/env python3
"""
aaa-lockout-check: offline lockout check of Cisco IOS / IOS-XE AAA configuration.

Before you bind TACACS+ device administration on a switch (the method list rules
L02 to L08 also read RADIUS lists; the source interface, VRF and key checks are
TACACS+ only), it answers one question: will this config lock me out? Feed it
saved running-configs (one or many files) and get a per-device findings list with
severity, the evidence line, why it matters and the exact fix lines. Pure text
parsing, standard library only, never connects to a device. Keys, secrets and
passwords are redacted from every output.

Cisco syntax and defaults vary by release and this tool only reads text, so
confirm each finding against the device's version before acting on it.

Exit codes: 0 no high findings, 1 high findings present, 2 error.
"""
import argparse
import csv
import difflib
import glob
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class Finding:
    device: str
    rule: str
    severity: str  # high | medium | low
    title: str
    evidence: str
    why: str
    fix: str


# Rule ID -> (severity as shown by --explain, why it matters in one sentence)
RULES = {
    "L00": ("low", "AAA not enabled: nothing here can lock you out yet; this check matters once you enable it."),
    "L01": ("high / medium", "With aaa new-model on and no local user there is nothing to fall back to when the "
                             "policy servers are out of reach (high); a user stored with 'password' still works as "
                             "the fallback but type 0 and 7 are reversible (medium)."),
    "L02": ("high / medium", "IOS tries the next login method only when the server group returns an ERROR (no server "
                             "replies), not when a server answers FAIL, so local last saves you from an outage but "
                             "not from a wrong password or a user missing on the server, and without a working "
                             "fallback an outage locks everyone out; a list ending in none lets anyone in (medium)."),
    "L03": ("high", "Exec authorization against a server group with no local or if-authenticated fallback refuses "
                    "every session while the servers are unreachable, even after a good local login."),
    "L04": ("high", "Command authorization against a server group with no local or if-authenticated fallback "
                    "refuses every command while the servers are unreachable, including the ones that back the "
                    "change out."),
    "L05": ("high", "aaa authorization console puts the console under the same server authorization, so a bad "
                    "policy on the server, or an outage with no fallback, closes the console too and it stops being "
                    "a way back in."),
    "L06": ("medium", "Console and vty lines on one server-backed login list fail together; change them in "
                      "separate windows and keep the console on a local path while testing."),
    "L07": ("high", "A method list that names a server group that is not defined, or a built-in group with no "
                    "servers behind it, never reaches a policy server, so logins quietly ride on the fallback or "
                    "fail outright."),
    "L08": ("high", "The line binding refers to a list that is not defined; behaviour then depends on release, so "
                    "define the list first."),
    "L09": ("medium", "Without ip tacacs source-interface the policy server sees whatever address the route picks; "
                      "it must match the device entry on the server, or the server treats it as an unknown device."),
    "L10": ("high", "The TACACS+ source interface is missing, shut down or has no IP address, so requests cannot "
                    "leave from the address the policy server knows."),
    "L11": ("high", "The source interface is in a VRF the server group does not forward into (or the reverse), or "
                    "the group points at legacy global-table servers, so requests leave in one routing table and "
                    "replies never come back: packets sent, nothing received, and every login waits on a timeout "
                    "of a few seconds before it falls back, and with command authorization on, so does every "
                    "command."),
    "L12": ("high", "The server group forwards into a VRF this config does not define, so there is no routing "
                    "table behind it."),
    "L13": ("medium", "A TACACS+ server entry without a key does not share a secret with the policy server, so the "
                      "server rejects or ignores its requests."),
    "L14": ("medium / high", "With no enable method after the server group nobody reaches privileged mode while the "
                      "servers are down; with the enable method but no enable secret, that fallback cannot succeed."),
    "L15": ("low", "Without command accounting to a server group there is no audit trail of who typed what."),
}

AUTHZ_FALLBACK = ("local", "if-authenticated", "none")
BUILTIN_GROUPS = ("tacacs+", "radius")
SEV_ORDER = {"high": 0, "medium": 1, "low": 2}

_SECRET_RX = re.compile(r"\b(key-string|key|secret|password)(\s+\d)?\s+\S.*$", re.I)


def redact(line: str) -> str:
    """Replace everything after a key / secret / password keyword (and its type digit) with <redacted>."""
    return _SECRET_RX.sub(lambda m: f"{m.group(1)}{m.group(2) or ''} <redacted>", line.strip())


def evidence(*lines) -> str:
    return " | ".join(redact(l) for l in lines if l) or "not found in config"


SRC_PLACEHOLDER = "<interface-with-the-address-ISE-knows>"


def near_or(name, candidates, placeholder):
    """Closest existing name to suggest in a fix (first candidate when name is None), else a placeholder."""
    if name is None:
        return candidates[0] if candidates else placeholder
    hit = difflib.get_close_matches(name, candidates, n=1, cutoff=0.5)
    return hit[0] if hit else placeholder


def blocks(lines, header_re):
    """Yield (header_match, body_lines) for every block whose header matches header_re."""
    rx = re.compile(header_re)
    i = 0
    while i < len(lines):
        m = rx.match(lines[i])
        if m:
            body = []
            i += 1
            while i < len(lines) and lines[i].startswith(" "):
                body.append(lines[i].strip())
                i += 1
            yield m, body
        else:
            i += 1


def parse_methods(text: str) -> list:
    """Split a method list into methods, keeping 'group X' and 'cache X' as one method."""
    toks, out, i = text.split(), [], 0
    while i < len(toks):
        if toks[i] in ("group", "cache") and i + 1 < len(toks):
            out.append(f"{toks[i]} {toks[i + 1]}")
            i += 2
        else:
            out.append(toks[i])
            i += 1
    return out


def groups_in(methods) -> list:
    return [m.split(" ", 1)[1] for m in methods if m.startswith("group ")]


def hostname_of(text: str):
    m = re.search(r"^hostname (\S+)", text, re.M)
    return m.group(1) if m else None


def first_ip(text: str):
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
    return m.group(1) if m else None


class Config:
    """Everything the lockout rules need, parsed from running-config text."""

    def __init__(self, text: str):
        lines = [l.rstrip() for l in text.replace("\r", "").splitlines()]
        top = [l for l in lines if l and not l.startswith((" ", "!"))]
        self.hostname = hostname_of(text)
        self.new_model = next((l for l in top if re.match(r"^aaa new-model\s*$", l)), None)
        self.enable_secret = next((l for l in top if re.match(r"^enable (algorithm-type \S+ )?secret\b", l)), None)
        self.enable_password = next((l for l in top if re.match(r"^enable password\b", l)), None)
        self.users = []  # (name, "secret" | "password" | None, line)
        self.login, self.exec_authz, self.cmd_authz = {}, {}, {}  # name or (level, name) -> (methods, line)
        self.enable_list = None  # (methods, line)
        self.console_authz = None
        self.acct_cmd = []  # (methods, line)
        self.method_lines = []  # (line, "auth" | "acct")
        self.tac_hosts, self.tac_key, self.tac_src = [], None, None
        self.rad_hosts = []
        self.vrfs = set()

        for l in top:
            m = re.match(r"^username (\S+)\b(.*)$", l)
            if m:
                kind = "secret" if re.search(r"\bsecret\s", m.group(2)) else (
                    "password" if re.search(r"\bpassword\s", m.group(2)) else None)
                self.users.append((m.group(1), kind, l))
                continue
            m = re.match(r"^aaa authentication login (\S+)\s+(.+)$", l)
            if m:
                self.login[m.group(1)] = (parse_methods(m.group(2)), l)
            m = re.match(r"^aaa authentication enable default\s+(.+)$", l)
            if m:
                self.enable_list = (parse_methods(m.group(1)), l)
            m = re.match(r"^aaa authorization exec (\S+)\s+(.+)$", l)
            if m:
                self.exec_authz[m.group(1)] = (parse_methods(m.group(2)), l)
            m = re.match(r"^aaa authorization commands (\d+) (\S+)\s+(.+)$", l)
            if m:
                self.cmd_authz[(m.group(1), m.group(2))] = (parse_methods(m.group(3)), l)
            if re.match(r"^aaa authorization console\s*$", l):
                self.console_authz = l
            m = re.match(r"^aaa accounting commands \d+ \S+\s+(.+)$", l)
            if m:
                self.acct_cmd.append((parse_methods(m.group(1)), l))
            if re.match(r"^aaa (authentication|authorization) ", l) and " group " in l:
                self.method_lines.append((l, "auth"))
            elif re.match(r"^aaa accounting ", l) and " group " in l:
                self.method_lines.append((l, "acct"))
            if re.match(r"^tacacs-server host \S", l):
                self.tac_hosts.append(l)
            if re.match(r"^tacacs-server key \S", l):
                self.tac_key = l
            m = re.match(r"^ip tacacs source-interface (\S+)", l)
            if m:
                self.tac_src = (m.group(1), l)
            if re.match(r"^radius-server host \S", l):
                self.rad_hosts.append(l)
            m = re.match(r"^(?:vrf definition|ip vrf) (\S+)\s*$", l)
            if m:
                self.vrfs.add(m.group(1))

        # aaa group server tacacs+|radius NAME
        self.groups = {}
        for m, body in blocks(lines, r"^aaa group server (tacacs\+|radius|ldap) (\S+)"):
            g = {"type": m.group(1), "line": m.group(0).strip(), "private": [], "names": [], "servers": [],
                 "vrf": None, "src": None}
            for b in body:
                if b.startswith("server-private "):
                    g["private"].append(b)
                elif re.match(r"^server name \S", b):
                    g["names"].append((b.split()[2], b))
                elif re.match(r"^server \S", b):
                    g["servers"].append(b)
                elif re.match(r"^(ip )?vrf forwarding \S", b):
                    g["vrf"] = (b.split()[-1], b)
                elif re.match(r"^ip (tacacs|radius) source-interface \S", b):
                    g["src"] = (b.split()[-1], b)
            self.groups[m.group(2)] = g

        # tacacs server NAME / radius server NAME
        self.tac_named, self.rad_named = {}, {}
        for m, body in blocks(lines, r"^(tacacs|radius) server (\S+)"):
            addr = next((first_ip(b) for b in body if b.startswith("address ")), None)
            key = next((b for b in body if re.match(r"^key\s", b)), None)
            target = self.tac_named if m.group(1) == "tacacs" else self.rad_named
            target[m.group(2)] = {"line": m.group(0).strip(), "addr": addr, "key": key}

        # interface NAME
        self.intfs = {}
        for m, body in blocks(lines, r"^interface (.+)$"):
            vrf = next((b.split()[-1] for b in body if re.match(r"^(ip )?vrf forwarding \S", b)), None)
            has_ip = any(re.match(r"^ip (address|unnumbered) \S", b) for b in body)
            shut = "shutdown" in body
            self.intfs[m.group(1).replace(" ", "")] = {"vrf": vrf, "ip": has_ip, "shut": shut}

        # line con 0 / line vty a b
        self.lines = []
        for m, body in blocks(lines, r"^line (con|console|vty)\b"):
            ln = {"hdr": m.string.strip(), "kind": "con" if m.group(1).startswith("con") else "vty",
                  "login": None, "exec": None, "cmds": {}, "password": False}
            for b in body:
                if re.match(r"^password\s+\S", b):
                    ln["password"] = True
                x = re.match(r"^login authentication (\S+)", b)
                if x:
                    ln["login"] = x.group(1)
                x = re.match(r"^authorization exec (\S+)", b)
                if x:
                    ln["exec"] = x.group(1)
                x = re.match(r"^authorization commands (\d+) (\S+)", b)
                if x:
                    ln["cmds"][x.group(1)] = x.group(2)
            self.lines.append(ln)

    def interface(self, name: str):
        """Resolve an interface name, accepting case differences and abbreviations (Gi1/0/1, Vl100)."""
        if name in self.intfs:
            return name
        want = re.match(r"([A-Za-z-]+)(.*)$", name)
        for k in self.intfs:
            have = re.match(r"([A-Za-z-]+)(.*)$", k)
            if k.lower() == name.lower():
                return k
            if want and have and have.group(2) == want.group(2) and \
                    have.group(1).lower().startswith(want.group(1).lower()):
                return k
        return None

    def tacacs_groups(self):
        return {n: g for n, g in self.groups.items() if g["type"] == "tacacs+"}

    def live_interfaces(self, vrf=None, any_vrf=True):
        """Interfaces that are up (not shut down) and have an IP address, optionally only those in one VRF."""
        return [k for k, v in self.intfs.items() if v["ip"] and not v["shut"] and (any_vrf or v["vrf"] == vrf)]


def login_fallback_ok(c, meths) -> bool:
    """True when a login list has a fallback that can let someone in while the servers are unreachable.

    local and local-case always count; enable only when an enable secret or enable password exists; line only
    when every console and vty line has a password. none is reported on its own (no lockout, no credentials).
    """
    for m in meths:
        if m in ("local", "local-case"):
            return True
        if m == "enable" and (c.enable_secret or c.enable_password):
            return True
        if m == "line" and c.lines and all(ln["password"] for ln in c.lines):
            return True
    return False


def audit_config(name: str, text: str) -> list:
    c = Config(text)
    dev = c.hostname or name
    f = []

    def add(rule, sev, title, ev, fix, why=None):
        f.append(Finding(dev, rule, sev, title, ev, why or RULES[rule][1],
                         "\n".join(fix) if isinstance(fix, list) else fix))

    if not c.new_model:
        add("L00", "low", "AAA not enabled", "aaa new-model not found in config",
            "none needed until 'aaa new-model' is configured")
        return f

    tac_groups = c.tacacs_groups()
    first_group = next(iter(tac_groups), None) or next(iter(c.groups), None) or "<group>"
    vty = [ln for ln in c.lines if ln["kind"] == "vty"]
    con = [ln for ln in c.lines if ln["kind"] == "con"]
    console_lines = con if c.console_authz else []

    # L01: a local identity to fall back to
    breakglass = ["username <breakglass-user> privilege 15 algorithm-type scrypt secret <secret>"]
    if not c.users:
        add("L01", "high", "No local user at all", "username not found in config", breakglass)
    elif not any(kind == "secret" for _, kind, _ in c.users):
        weak = [l for _, kind, l in c.users if kind == "password"]
        if weak:
            add("L01", "medium", "Only password-type local users, no local user with a secret", evidence(*weak[:3]),
                breakglass, "A local user stored with 'password' still works as the fallback, but type 0 and 7 are "
                            "reversible; store the break-glass account with 'secret'.")
        else:
            add("L01", "medium", "No local user with a secret or a password",
                evidence(*[l for _, _, l in c.users][:3]), breakglass,
                "The local users here have neither a secret nor a password, so they are no dependable fallback; "
                "store the break-glass account with 'secret'.")

    # L02: login lists with a server group and no fallback that can work during an outage
    login_live = {"default"} | {ln["login"] for ln in c.lines if ln["login"]}
    for lname, (meths, line) in c.login.items():
        if not groups_in(meths):
            continue
        live = lname in login_live
        unbound = "" if live else " (not bound to a line yet; binding it as written locks you out in an outage)"
        if "none" in meths:
            has_local = any(m in ("local", "local-case") for m in meths)
            fixed = [m for m in meths if m != "none"] if has_local else ["local" if m == "none" else m for m in meths]
            add("L02", "medium", f"Login list '{lname}' ends in none: no credentials needed while the servers are down",
                evidence(line), [f"aaa authentication login {lname} {' '.join(fixed)}"],
                "With none after the server group anyone gets in without a password whenever the servers stop "
                "replying; local keeps a way in during an outage and still asks for credentials.")
        elif not login_fallback_ok(c, meths):
            broken = [m for m in meths if m in ("enable", "line")]
            fixed, put = [], False
            for m in meths:
                if m in ("enable", "line"):
                    if not put:
                        fixed.append("local")
                        put = True
                else:
                    fixed.append(m)
            if not put:
                fixed.append("local")
            if not broken:
                title = f"Login list '{lname}' has no local fallback after the server group"
                why = ("IOS tries the next login method only when the server group returns an ERROR (no server "
                       "replies), not when a server answers FAIL, so local last saves you from an outage but not "
                       "from a wrong password or a user missing on the server, and without it an outage locks "
                       "everyone out.")
            elif broken[0] == "enable":
                title = f"Login list '{lname}' falls back to 'enable' but there is no enable secret or enable password"
                why = ("IOS reaches the enable method only when no server replies, and with no enable secret or "
                       "enable password it has nothing to check, so an outage locks everyone out.")
            else:
                title = f"Login list '{lname}' falls back to 'line' but not every console and vty line has a password"
                why = ("IOS reaches the line method only when no server replies, and a line without a password has "
                       "nothing to check, so an outage locks everyone out of that line.")
            add("L02", "high" if live else "medium", title + unbound, evidence(line),
                [f"aaa authentication login {lname} {' '.join(fixed)}"], why)

    # L03: exec authorization without fallback
    exec_live = {"default"} | {ln["exec"] for ln in vty + console_lines if ln["exec"]}
    for lname, (meths, line) in c.exec_authz.items():
        if groups_in(meths) and not any(m in AUTHZ_FALLBACK for m in meths):
            live = lname in exec_live
            add("L03", "high" if live else "medium",
                f"Exec authorization list '{lname}' has no local or if-authenticated fallback"
                + ("" if live else " (not bound to a line yet)"),
                evidence(line), [f"aaa authorization exec {lname} {' '.join(meths)} if-authenticated"])

    # L04: command authorization without fallback
    cmd_live = {(lvl, n) for (lvl, n) in c.cmd_authz if n == "default"}
    cmd_live |= {(lvl, n) for ln in vty + console_lines for lvl, n in ln["cmds"].items()}
    for (lvl, lname), (meths, line) in c.cmd_authz.items():
        if groups_in(meths) and not any(m in AUTHZ_FALLBACK for m in meths):
            live = (lvl, lname) in cmd_live
            add("L04", "high" if live else "medium",
                f"Command authorization (level {lvl}) list '{lname}' has no local or if-authenticated fallback"
                + ("" if live else " (not bound to a line yet)"),
                evidence(line), [f"aaa authorization commands {lvl} {lname} {' '.join(meths)} if-authenticated"])

    # L05: console authorization against a server group
    if c.console_authz:
        used = set()
        for ln in con or [{"exec": None, "cmds": {}}]:
            e = c.exec_authz.get(ln["exec"] or "default")
            if e and groups_in(e[0]):
                used.add(e[1])
            for (lvl, n), (meths, line) in c.cmd_authz.items():
                if ln["cmds"].get(lvl, "default") == n and groups_in(meths):
                    used.add(line)
        if used:
            add("L05", "high", "Console authorization is on and goes to a server group",
                evidence(c.console_authz, *sorted(used)), ["no aaa authorization console"])

    # L06: console and vty on the same server-backed login list
    for cl in con:
        cname = cl["login"] or "default"
        for vl in vty:
            vname = vl["login"] or "default"
            if cname == vname and cname in c.login and groups_in(c.login[cname][0]):
                add("L06", "medium", f"Console and vty share the server-backed login list '{cname}'",
                    f"{cl['hdr']} and {vl['hdr']} both use '{cname}' | {redact(c.login[cname][1])}",
                    ["aaa authentication login CONSOLE local", "line con 0", " login authentication CONSOLE"])
                break

    # L07: method lists naming groups that do not exist or have no servers
    seen = set()
    for kind in ("auth", "acct"):
        sev = "high" if kind == "auth" else "medium"
        for line, k in c.method_lines:
            if k != kind:
                continue
            for g in groups_in(parse_methods(line)):
                if g in seen:
                    continue
                if g == "tacacs+" and not (c.tac_hosts or c.tac_named):
                    seen.add(g)
                    add("L07", sev, "Built-in 'group tacacs+' is used but no TACACS+ server is defined",
                        evidence(line), ["tacacs server <name>", " address ipv4 <server-ip>", " key <key>"])
                elif g == "radius" and not (c.rad_hosts or c.rad_named):
                    seen.add(g)
                    add("L07", sev, "Built-in 'group radius' is used but no RADIUS server is defined",
                        evidence(line), ["radius server <name>", " address ipv4 <server-ip>", " key <key>"])
                elif g not in BUILTIN_GROUPS and g not in c.groups:
                    seen.add(g)
                    near = difflib.get_close_matches(g, list(c.groups), n=1, cutoff=0.6)
                    fix = [re.sub(rf"\bgroup {re.escape(g)}(?=\s|$)", f"group {near[0]}", line)] if near else \
                        [f"aaa group server tacacs+ {g}", " server-private <server-ip> key <key>"]
                    add("L07", sev, f"Method list names server group '{g}', which is not defined"
                        + (f" (did you mean '{near[0]}'?)" if near else ""), evidence(line), fix)
                elif g in c.groups:
                    seen.add(g)
                    grp = c.groups[g]
                    named = c.tac_named if grp["type"] == "tacacs+" else c.rad_named
                    missing = [(n, l) for n, l in grp["names"] if n not in named]
                    word = "tacacs" if grp["type"] == "tacacs+" else "radius"
                    if not (grp["private"] or grp["names"] or grp["servers"]):
                        add("L07", sev, f"Server group '{g}' has no servers", evidence(grp["line"]),
                            [grp["line"], " server name <server>"])
                    for n, l in missing:
                        add("L07", sev, f"Server group '{g}' points at server '{n}', which is not defined",
                            evidence(l), [f"{word} server {n}", " address ipv4 <server-ip>", " key <key>"])

    # L08: line bindings to lists that are not defined
    for ln in c.lines:
        checks = [("login authentication", ln["login"], c.login, lambda n: [
                      f"aaa authentication login {n} group {first_group} local"]),
                  ("authorization exec", ln["exec"], c.exec_authz, lambda n: [
                      f"aaa authorization exec {n} group {first_group} if-authenticated"])]
        for lvl, n in ln["cmds"].items():
            checks.append((f"authorization commands {lvl}", n, {k[1]: v for k, v in c.cmd_authz.items()
                                                                 if k[0] == lvl},
                           lambda n, lvl=lvl: [f"aaa authorization commands {lvl} {n} group {first_group} "
                                               "if-authenticated"]))
        for what, n, defined, fix in checks:
            if n and n != "default" and n not in defined:
                add("L08", "high", f"{ln['hdr']}: '{what} {n}' refers to a list that is not defined",
                    f"{ln['hdr']} | {what} {n}", fix(n))

    # L09 / L10 / L11: TACACS+ source interface and VRF
    tac_in_use = bool(tac_groups or c.tac_hosts or c.tac_named) or any(
        "tacacs+" in groups_in(parse_methods(l)) for l, _ in c.method_lines)
    sources = ([("global", None, c.tac_src)] if c.tac_src else []) + \
              [(f"group {n}", g, g["src"]) for n, g in tac_groups.items() if g["src"]]
    if tac_in_use and not sources:
        add("L09", "medium", "No TACACS+ source interface set", "ip tacacs source-interface not found in config",
            [f"ip tacacs source-interface {SRC_PLACEHOLDER}"])
    for where, g, (iname, line) in sources:
        k = c.interface(iname)
        if k is None:
            title, ev = f"TACACS+ source interface {iname} ({where}) is not in this config", evidence(line)
        elif c.intfs[k]["shut"]:
            title, ev = f"TACACS+ source interface {k} ({where}) is shut down", evidence(line, f"interface {k} | shutdown")
        elif not c.intfs[k]["ip"]:
            title, ev = f"TACACS+ source interface {k} ({where}) has no IP address", evidence(line, f"interface {k}")
        else:
            continue
        new = near_or(iname, [i for i in c.live_interfaces() if i != k], SRC_PLACEHOLDER)
        fix = [f"ip tacacs source-interface {new}"] if g is None else [g["line"], f" ip tacacs source-interface {new}"]
        add("L10", "high", title, ev, fix)

    # L11: each TACACS+ group (and the built-in group tacacs+ when used) against its source interface VRF
    vrf_checks = list(tac_groups.items())
    if c.tac_src and any("tacacs+" in groups_in(parse_methods(l)) for l, _ in c.method_lines):
        vrf_checks.append(("tacacs+", None))
    for gname, g in vrf_checks:
        src = (g and g["src"]) or c.tac_src
        intf = c.interface(src[0]) if src else None
        if src and intf is None:
            continue  # L10 already covers a missing source interface
        svrf = c.intfs[intf]["vrf"] if intf else None
        gvrf = g["vrf"][0] if g and g["vrf"] else None
        problems, servers_fix, vrf_fix = [], [], []
        if g is None:
            if not svrf:
                continue
            problems.append(f"source {intf} is in VRF {svrf} but the built-in group tacacs+ uses global-table "
                            "servers and cannot forward into a VRF")
            servers_fix = [f" server name {n}" for n in c.tac_named] + \
                          [f" server-private {first_ip(h) or '<server-ip>'} key <key>" for h in c.tac_hosts]
            vrf_fix = [f" ip vrf forwarding {svrf}", f" ip tacacs source-interface {intf}"]
        else:
            if svrf and svrf != gvrf:
                problems.append(f"source {intf} is in VRF {svrf} but group {gname} " + (
                    f"forwards into VRF {gvrf}" if gvrf else f"has no 'ip vrf forwarding {svrf}'"))
                vrf_fix = [f" ip vrf forwarding {svrf}", f" ip tacacs source-interface {intf}"]
            elif gvrf and intf and not svrf:
                problems.append(f"group {gname} forwards into VRF {gvrf} but source {intf} is in the global table")
                vrf_fix = [f" ip tacacs source-interface "
                           f"{near_or(None, c.live_interfaces(gvrf, any_vrf=False), '<interface-in-' + gvrf + '>')}"]
            vrf = svrf or gvrf
            if vrf and g["servers"]:
                problems.append(f"group {gname} points at legacy global-table servers ('server <ip>') while it "
                                f"uses VRF {vrf}")
                servers_fix = [f" no {s}" for s in g["servers"]] + \
                              [f" server-private {first_ip(s) or '<server-ip>'} key <key>" for s in g["servers"]]
        if not problems:
            continue
        fix = [g["line"] if g else "aaa group server tacacs+ TACACS-VRF"] + servers_fix + vrf_fix
        if g is None:
            fix.append("then point the method lists at 'group TACACS-VRF' instead of 'group tacacs+'")
        servers = (g["private"] + [l for _, l in g["names"]] + g["servers"])[:2] if g else c.tac_hosts[:2]
        ev = ([g["line"]] if g else []) + servers + ([g["vrf"][1]] if g and g["vrf"] else []) + \
            ([src[1]] if src else [])
        add("L11", "high", "TACACS+ VRF mismatch: " + "; ".join(problems), evidence(*ev), fix)

    # L12: server group forwards into a VRF that is not defined
    for gname, g in c.groups.items():
        if g["vrf"] and g["vrf"][0] not in c.vrfs:
            v = g["vrf"][0]
            add("L12", "high", f"Server group '{gname}' forwards into VRF {v}, which is not defined",
                evidence(g["line"], g["vrf"][1]),
                [g["line"], f" ip vrf forwarding {near_or(v, sorted(c.vrfs), '<existing-mgmt-vrf>')}"])

    # L13: TACACS+ servers without a key
    if not c.tac_key:
        for h in c.tac_hosts:
            if not re.search(r"\skey\s", h):
                add("L13", "medium", f"TACACS+ host {first_ip(h) or h.split()[2]} has no key", evidence(h),
                    [f"tacacs-server host {h.split()[2]} key <key>"])
    for n, s in c.tac_named.items():
        if not s["key"]:
            add("L13", "medium", f"TACACS+ server '{n}' has no key", evidence(s["line"]),
                [s["line"], " key <key>"])
    for gname, g in tac_groups.items():
        for p in g["private"]:
            if not re.search(r"\skey\s", p):
                add("L13", "medium", f"server-private {first_ip(p)} in group '{gname}' has no key", evidence(p),
                    [g["line"], f" {p} key <key>"])

    # L14: enable authentication
    if c.enable_list and groups_in(c.enable_list[0]):
        meths, line = c.enable_list
        if not any(m in ("enable", "none") for m in meths):
            add("L14", "medium", "Enable authentication has no enable fallback after the server group",
                evidence(line), [f"aaa authentication enable default {' '.join(meths)} enable"],
                "With no enable method after the server group, nobody reaches privileged mode while the servers "
                "are down unless the session already starts at privilege 15.")
        elif "enable" in meths and not (c.enable_secret or c.enable_password):
            add("L14", "high", "Enable fallback is configured but there is no enable secret", evidence(line),
                ["enable algorithm-type scrypt secret <secret>"],
                "The enable fallback checks the enable secret, and there is none, so that fallback cannot succeed.")

    # L15: command accounting to a server group
    if not any(groups_in(meths) for meths, _ in c.acct_cmd):
        add("L15", "low", "No command accounting to a server group", "aaa accounting commands not found in config",
            [f"aaa accounting commands 15 default start-stop group {first_group if c.groups else 'tacacs+'}"])
    return f


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="aaa-lockout-check",
                                description="Offline Cisco IOS / IOS-XE AAA lockout check: will this config lock me out?")
    p.add_argument("configs", nargs="*", help="saved running-config files (globs allowed)")
    p.add_argument("--csv", help="write findings to CSV")
    p.add_argument("--json", help="write findings to JSON")
    p.add_argument("--min-severity", choices=["high", "medium", "low"], default="low")
    p.add_argument("--explain", action="store_true", help="print each rule ID with one line on why, then exit")
    a = p.parse_args(argv)

    if a.explain:
        for rid, (sev, why) in RULES.items():
            print(f"{rid} [{sev}] {why}")
        return 0

    files = []
    for pat in a.configs:
        hits = [Path(h) for h in sorted(glob.glob(pat))] if any(ch in pat for ch in "*?[") else [Path(pat)]
        files.extend(h for h in hits if h.is_file())
    if not files:
        print("error: no config files found", file=sys.stderr)
        return 2

    limit = SEV_ORDER[a.min_severity]
    findings, devices = [], set()
    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"error: {fp}: {e}", file=sys.stderr)
            return 2
        devices.add(hostname_of(text) or fp.stem)
        findings += [x for x in audit_config(fp.stem, text) if SEV_ORDER[x.severity] <= limit]
    findings.sort(key=lambda x: (x.device, SEV_ORDER[x.severity], x.rule))

    for dev in sorted(devices):
        mine = [x for x in findings if x.device == dev]
        counts = {s: sum(1 for x in mine if x.severity == s) for s in SEV_ORDER}
        print(f"\n{dev}: {counts['high']} high, {counts['medium']} medium, {counts['low']} low")
        for x in mine:
            fix = x.fix.replace("\n", "\n                ")
            print(f"  [{x.severity.upper():6}] {x.rule} {x.title}\n           evidence: {x.evidence}"
                  f"\n           why: {x.why}\n           fix: {fix}")

    try:
        if a.csv:
            with open(a.csv, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=list(Finding.__dataclass_fields__))
                w.writeheader()
                w.writerows(asdict(x) for x in findings)
        if a.json:
            Path(a.json).write_text(json.dumps([asdict(x) for x in findings], indent=2), encoding="utf-8")
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    return 1 if any(x.severity == "high" for x in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
