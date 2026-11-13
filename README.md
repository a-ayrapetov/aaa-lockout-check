# aaa-lockout-check

[![ci](https://github.com/a-ayrapetov/aaa-lockout-check/actions/workflows/ci.yml/badge.svg)](https://github.com/a-ayrapetov/aaa-lockout-check/actions/workflows/ci.yml)

Offline lockout check for Cisco IOS and IOS-XE AAA config. Before you bind TACACS+ (or RADIUS) device administration on a switch, point it at the saved running-config and it answers one question: will this config lock me out? Per device you get every risk with severity, the evidence line, why it matters in one sentence and the exact lines that fix it.

```bash
pip install git+https://github.com/a-ayrapetov/aaa-lockout-check
aaa-lockout-check sw1.cfg
```

## Rules

| ID | Severity | Check |
|---|---|---|
| L00 | low | AAA not enabled: nothing here can lock you out yet; this check matters once you enable it |
| L01 | high | `aaa new-model` on and no local user stored with `secret` (a `password`-only user counts as weak) |
| L02 | high | login list on a line or the default list has a server group and no `local`, `local-case`, `enable` or `line` method |
| L03 | high | exec authorization list on a vty line or the default list has a server group and no `local` or `if-authenticated` |
| L04 | high | command authorization list has a server group and no `local` or `if-authenticated` |
| L05 | high | `aaa authorization console` together with server-group exec or command authorization |
| L06 | medium | console and vty bound to the same server-backed login list |
| L07 | high | method list names a group that is not defined, a group with no servers, or built-in `group tacacs+` / `group radius` with no server defined |
| L08 | high | line binds `login authentication`, `authorization exec` or `authorization commands` to a list that is not defined |
| L09 | medium | no `ip tacacs source-interface` anywhere |
| L10 | high | TACACS+ source interface missing from the config, shut down, or without an IP address |
| L11 | high | source interface in VRF V but the server group has no `ip vrf forwarding V`, or uses `server name` or global servers instead of `server-private` |
| L12 | high | server group has `ip vrf forwarding V` and V is not defined |
| L13 | medium | TACACS+ server (legacy host, named server or `server-private`) without a key |
| L14 | medium / high | enable list with a server group and no `enable` fallback (medium), or with `enable` fallback and neither `enable secret` nor `enable password` (high) |
| L15 | low | no command accounting to a server group |

L02, L03 and L04 report a named list that no line uses yet as medium, because binding it as written is the lockout. L07 on an accounting line is medium, because it costs you the audit trail, not the login. Run `aaa-lockout-check --explain` for one line per rule on why it matters.

How fallback works on Cisco: the next method in a list is tried only when the one before it returns an ERROR, which means no server in the group replied. When a server answers FAIL (wrong password, user not on the server, policy says no) the attempt ends there. So `local` at the end of a list protects you from an outage. It does not protect you from a wrong password or a user missing on the server.

Cisco syntax and defaults vary by release, and this tool only reads text. Confirm each finding against the device's version before you act on it.

## Why this exists

Lockouts during TACACS+ migrations of legacy switches cost whole days. The failure looks exactly like a bad password, so the first hours go to chasing the wrong problem. This was written after moving fleets of legacy and current Cisco switches to Cisco ISE TACACS+, to catch the config mistakes before the change window instead of inside it.

## Before you bind the vty lines

1. Test the group from the device first: `test aaa group <group> <user> <password>`. Keywords vary by release, so check the options with `?` on the device.
2. Keep a second session open and logged in until a fresh session works with the new config.
3. Change the vty lines and the console in separate windows. Keep the console on a local list while you test.
4. Know the recovery order before you start: the session you kept open, then a local account on the vty lines, then the console on its local list.

## Safety

Text parsing only, standard library only, never connects to a device. Keys, secrets and passwords are redacted from the evidence in every output (table, CSV and JSON), so reports are safe to share. Fix lines use placeholders like `<key>` and `<secret>`.

## Usage

```bash
aaa-lockout-check sw1.cfg
aaa-lockout-check "configs/*.cfg" --csv out.csv --json out.json --min-severity medium
aaa-lockout-check --explain
```

Exit codes: `0` no high findings, `1` high findings present, `2` error, so it gates a change pipeline or a pre-change check cleanly.

Pairs with [ios-hardening-audit](https://github.com/a-ayrapetov/ios-hardening-audit): run the hardening audit for the full baseline, and this check right before an AAA change.

## Tests

```bash
pip install pytest && python -m pytest
```

## License

MIT. See LICENSE. Security reports: see SECURITY.md.
