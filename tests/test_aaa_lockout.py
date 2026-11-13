import csv
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import aaa_lockout as a  # noqa: E402

SRC_PLACEHOLDER = "<interface-with-the-address-ISE-knows>"

BASE = """hostname unit-sw1
aaa new-model
username breakglass privilege 15 secret 9 $9$unitfixturehash
enable secret 9 $9$unitfixturehash
aaa accounting commands 15 default start-stop group TAC
interface Vlan100
 ip address 198.51.100.50 255.255.255.0
"""
TAC = """aaa group server tacacs+ TAC
 server-private 192.0.2.10 key 7 UnitFixtureKey0123
 ip tacacs source-interface Vlan100
"""


def findings(name):
    return a.audit_config(name, (HERE / f"{name}.cfg").read_text())


def rules(name, sev=None):
    return {x.rule for x in findings(name) if sev is None or x.severity == sev}


def audit(text):
    return a.audit_config("unit", text)


def hits(text, rule):
    return [x for x in audit(text) if x.rule == rule]


# Fixture configs

def test_safe_config_has_nothing_above_low():
    assert [x for x in findings("safe-sw1") if x.severity != "low"] == []


def test_legacy_ios15_config_is_safe():
    assert [x for x in findings("legacy-sw1") if x.severity != "low"] == []


def test_dangerous_config_hits_high_rules():
    high = rules("danger-sw1", "high")
    for rule in ("L02", "L03", "L04", "L05", "L07", "L08", "L10", "L12", "L14"):
        assert rule in high, rule
    assert {"L01", "L06", "L13"} <= rules("danger-sw1", "medium")
    assert "L15" in rules("danger-sw1", "low")


def test_device_is_the_hostname():
    assert {x.device for x in findings("danger-sw1")} == {"danger-sw1"}
    assert {x.device for x in a.audit_config("file-stem", "aaa new-model\n")} == {"file-stem"}


def test_mgmt_vrf_mismatch_is_high():
    l11 = [x for x in findings("mgmt-vrf-bad") if x.rule == "L11"]
    assert len(l11) == 1 and l11[0].severity == "high"
    assert "no 'ip vrf forwarding Mgmt-vrf'" in l11[0].title
    # the fix adds the VRF and source to the group and leaves the working server name entries alone
    assert l11[0].fix.splitlines() == ["aaa group server tacacs+ TACACS-ADMIN", " ip vrf forwarding Mgmt-vrf",
                                       " ip tacacs source-interface GigabitEthernet0/0"]
    assert "replies never come back" in l11[0].why and "every login waits on a timeout" in l11[0].why


def test_mgmt_vrf_fixed_twin_is_clean():
    assert [x for x in findings("mgmt-vrf-fixed") if x.severity != "low"] == []


def test_no_aaa_gives_one_low_line():
    f = findings("no-aaa-sw1")
    assert [(x.rule, x.severity) for x in f] == [("L00", "low")]
    assert "nothing here can lock you out yet" in f[0].why


# Single rules

def test_l01_password_only_user_is_medium_and_no_user_is_high():
    text = "aaa new-model\nusername admin privilege 15 password 0 UnitFixturePw01\n"
    f = hits(text, "L01")
    assert f and f[0].severity == "medium" and "UnitFixturePw01" not in f[0].evidence
    assert "still works as the fallback" in f[0].why and "'secret'" in f[0].why
    assert hits("aaa new-model\n", "L01")[0].severity == "high"
    assert not hits(BASE, "L01")


def test_l02_local_first_or_last_is_fine_and_why_explains_error_vs_fail():
    for methods in ("group TAC local", "local group TAC", "group TAC local-case", "group TAC enable"):
        assert not hits(BASE + TAC + f"aaa authentication login default {methods}\n", "L02"), methods
    f = hits(BASE + TAC + "aaa authentication login default group TAC\n", "L02")
    assert f[0].severity == "high" and f[0].fix == "aaa authentication login default group TAC local"
    assert "ERROR" in f[0].why and "FAIL" in f[0].why


def test_l02_enable_fallback_without_enable_secret_is_high():
    f = [x for x in findings("l02-enable") if x.severity != "low"]
    assert [(x.rule, x.severity) for x in f] == [("L02", "high")]
    assert "no enable secret or enable password" in f[0].title
    assert f[0].fix == "aaa authentication login default group TAC local"
    with_pw = BASE + TAC + "aaa authentication login default group TAC enable\n"
    assert not hits(with_pw, "L02")


def test_l02_line_fallback_without_line_password_is_high():
    f = [x for x in findings("l02-line") if x.severity != "low"]
    assert [(x.rule, x.severity) for x in f] == [("L02", "high")]
    assert "'line'" in f[0].title and f[0].fix == "aaa authentication login default group TAC local"
    every_line = BASE + TAC + ("aaa authentication login default group TAC line\n"
                               "line con 0\n password 7 UnitFixtureLinePw1\nline vty 0 4\n password 7 UnitFixtureLinePw2\n")
    assert not hits(every_line, "L02")
    one_missing = every_line.replace(" password 7 UnitFixtureLinePw2\n", "")
    assert hits(one_missing, "L02")[0].severity == "high"


def test_l02_none_is_medium_and_fix_replaces_none_with_local():
    f = [x for x in findings("l02-none") if x.severity != "low"]
    assert [(x.rule, x.severity) for x in f] == [("L02", "medium")]
    assert "ends in none" in f[0].title and f[0].fix == "aaa authentication login default group TAC local"
    assert hits(BASE + TAC + "aaa authentication login default group TAC local none\n", "L02")[0].fix == \
        "aaa authentication login default group TAC local"


def test_l02_unbound_named_list_is_medium_and_bound_is_high():
    text = BASE + TAC + "aaa authentication login VTY group TAC\n"
    assert hits(text, "L02")[0].severity == "medium"
    bound = text + "line vty 0 4\n login authentication VTY\n"
    assert hits(bound, "L02")[0].severity == "high"


def test_l03_l04_need_local_or_if_authenticated():
    bad = BASE + TAC + "aaa authorization exec default group TAC\naaa authorization commands 15 default group TAC\n"
    assert hits(bad, "L03")[0].severity == "high" and hits(bad, "L04")[0].severity == "high"
    good = bad.replace("group TAC\n", "group TAC if-authenticated\n")
    assert not hits(good, "L03") and not hits(good, "L04")


def test_l05_console_authorization_with_server_authorization():
    text = BASE + TAC + "aaa authorization console\naaa authorization exec default group TAC if-authenticated\n"
    assert hits(text, "L05")[0].severity == "high"
    assert not hits(BASE + TAC + "aaa authorization console\n", "L05")


def test_l06_console_and_vty_on_same_server_list():
    text = BASE + TAC + "aaa authentication login default group TAC local\nline con 0\nline vty 0 4\n"
    assert hits(text, "L06")[0].severity == "medium"
    split = BASE + TAC + ("aaa authentication login default group TAC local\naaa authentication login CON local\n"
                          "line con 0\n login authentication CON\nline vty 0 4\n")
    assert not hits(split, "L06")


def test_l07_undefined_group_and_builtin_without_servers():
    typo = hits(BASE + TAC + "aaa authentication login default group TACC local\n", "L07")
    assert typo[0].severity == "high" and typo[0].fix == "aaa authentication login default group TAC local"
    builtin = hits(BASE + "aaa authentication login default group tacacs+ local\n", "L07")
    assert builtin[0].severity == "high" and "tacacs+" in builtin[0].title
    legacy = BASE + "tacacs-server host 192.0.2.10 key 7 UnitFixtureKey0456\n"
    f = hits(legacy + "aaa authentication login default group tacacs+ local\n", "L07")
    # only the accounting line in BASE still names the undefined group TAC, and accounting is medium
    assert [(x.severity, "'TAC'" in x.title) for x in f] == [("medium", True)]


def test_l08_line_binding_to_undefined_list():
    f = hits(BASE + TAC + "line vty 0 4\n login authentication NOPE\n", "L08")
    assert f[0].severity == "high" and "not defined" in f[0].title


def test_l09_no_source_interface_is_medium():
    text = BASE + "aaa group server tacacs+ TAC\n server-private 192.0.2.10 key 7 UnitFixtureKey0789\n"
    assert hits(text, "L09")[0].severity == "medium"
    assert not hits(BASE + TAC, "L09")


def test_l10_source_interface_missing_shut_or_without_address():
    shut = BASE.replace(" ip address", " shutdown\n ip address") + TAC
    assert "shut down" in hits(shut, "L10")[0].title
    noip = BASE.replace(" ip address 198.51.100.50 255.255.255.0", " no ip address") + TAC
    assert "no IP address" in hits(noip, "L10")[0].title
    assert SRC_PLACEHOLDER in hits(shut, "L10")[0].fix and SRC_PLACEHOLDER in hits(noip, "L10")[0].fix
    missing = BASE + TAC.replace("Vlan100", "Vlan200")
    f = hits(missing, "L10")
    assert "not in this config" in f[0].title
    # point the source at the closest interface that exists and has an address; never create a new SVI
    assert f[0].fix.splitlines() == ["aaa group server tacacs+ TAC", " ip tacacs source-interface Vlan100"]
    assert hits(BASE + "ip tacacs source-interface Vlan200\n", "L10")[0].fix == "ip tacacs source-interface Vlan100"
    assert not any(x.fix.startswith("interface ") for x in findings("danger-sw1") if x.rule == "L10")
    abbreviated = BASE + TAC.replace("source-interface Vlan100", "source-interface Vl100")
    assert not hits(abbreviated, "L10")


def test_l11_server_private_without_vrf_shows_redacted_key():
    text = BASE.replace(" ip address", " vrf forwarding MGMT\n ip address") + "vrf definition MGMT\n" + TAC
    f = hits(text, "L11")
    assert f[0].severity == "high" and "no 'ip vrf forwarding MGMT'" in f[0].title
    assert "key 7 <redacted>" in f[0].evidence and "UnitFixtureKey0123" not in f[0].evidence


def test_l11_server_name_with_matching_vrf_is_fine():
    text = (BASE.replace(" ip address", " vrf forwarding MGMT\n ip address") + "vrf definition MGMT\n"
            "aaa group server tacacs+ TAC\n server name T1\n ip vrf forwarding MGMT\n"
            " ip tacacs source-interface Vlan100\n"
            "tacacs server T1\n address ipv4 192.0.2.10\n key 7 UnitFixtureKey0555\n")
    assert not hits(text, "L11")
    assert [x for x in findings("mgmt-vrf-fixed") if x.rule == "L11"] == []


def test_l11_legacy_global_servers_in_a_vrf_group():
    text = (BASE.replace(" ip address", " vrf forwarding MGMT\n ip address") + "vrf definition MGMT\n"
            "tacacs-server host 192.0.2.10 key 7 UnitFixtureKey0666\n"
            "aaa group server tacacs+ TAC\n server 192.0.2.10\n ip vrf forwarding MGMT\n"
            " ip tacacs source-interface Vlan100\n")
    f = hits(text, "L11")
    assert f and "legacy global-table servers" in f[0].title
    assert " server-private 192.0.2.10 key <key>" in f[0].fix.splitlines()


def test_l11_reverse_mismatch_suggests_an_interface_in_the_vrf():
    text = (BASE + "vrf definition MGMT\ninterface GigabitEthernet0/0\n vrf forwarding MGMT\n"
            " ip address 203.0.113.5 255.255.255.0\n"
            "aaa group server tacacs+ TAC\n server-private 192.0.2.10 key 7 UnitFixtureKey0777\n"
            " ip vrf forwarding MGMT\n ip tacacs source-interface Vlan100\n")
    f = hits(text, "L11")
    assert "global table" in f[0].title
    assert f[0].fix.splitlines() == ["aaa group server tacacs+ TAC", " ip tacacs source-interface GigabitEthernet0/0"]


def test_l11_builtin_tacacs_cannot_follow_a_vrf():
    text = (BASE.replace(" ip address", " vrf forwarding MGMT\n ip address") + "vrf definition MGMT\n"
            "ip tacacs source-interface Vlan100\ntacacs-server host 192.0.2.10 key 7 UnitFixtureKey0999\n"
            "aaa authentication login default group tacacs+ local\n")
    f = hits(text, "L11")
    assert f and "built-in group tacacs+" in f[0].title


def test_l12_vrf_not_defined_suggests_an_existing_vrf_never_a_new_one():
    group = "aaa group server tacacs+ TAC2\n server-private 192.0.2.11 key 7 X1\n ip vrf forwarding Mgmt-vfr\n"
    f = hits(BASE + TAC + group, "L12")
    assert f[0].severity == "high" and f[0].fix.endswith(" ip vrf forwarding <existing-mgmt-vrf>")
    f = hits(BASE + TAC + "vrf definition Mgmt-vrf\n" + group, "L12")
    assert f[0].fix.splitlines() == ["aaa group server tacacs+ TAC2", " ip vrf forwarding Mgmt-vrf"]
    assert not any("vrf definition" in x.fix for x in findings("danger-sw1"))


def test_l13_missing_keys_and_global_key_covers_legacy_hosts():
    assert hits(BASE + "tacacs-server host 192.0.2.10\n", "L13")[0].severity == "medium"
    assert not hits(BASE + "tacacs-server host 192.0.2.10\ntacacs-server key 7 UnitFixtureKey0321\n", "L13")
    named = hits(BASE + "tacacs server T1\n address ipv4 192.0.2.10\n", "L13")
    assert named and named[0].fix.splitlines() == ["tacacs server T1", " key <key>"]


def test_l14_enable_fallback():
    no_fallback = BASE + TAC + "aaa authentication enable default group TAC\n"
    assert hits(no_fallback, "L14")[0].severity == "medium"
    no_secret = (BASE.replace("enable secret 9 $9$unitfixturehash\n", "") + TAC
                 + "aaa authentication enable default group TAC enable\n")
    assert hits(no_secret, "L14")[0].severity == "high"
    assert not hits(BASE + TAC + "aaa authentication enable default group TAC enable\n", "L14")


def test_l15_command_accounting():
    assert not hits(BASE + TAC, "L15")
    assert hits("aaa new-model\n", "L15")[0].severity == "low"


# Redaction and CLI

def test_redact():
    assert a.redact("username u privilege 15 secret 9 $9$abc") == "username u privilege 15 secret 9 <redacted>"
    assert a.redact(" server-private 192.0.2.10 key 7 0822455D0A16") == "server-private 192.0.2.10 key 7 <redacted>"
    assert a.redact("tacacs-server key PlainFixture") == "tacacs-server key <redacted>"


def test_no_key_or_secret_value_in_any_output(tmp_path, capsys):
    cfgs = sorted(HERE.glob("*.cfg"))
    values = set()
    for cfg in cfgs:
        for m in re.finditer(r"\b(?:key|secret|password)\s+(?:\d\s+)?(\S+)", cfg.read_text()):
            values.add(m.group(1))
    assert len(values) >= 10
    out_csv, out_json = tmp_path / "f.csv", tmp_path / "f.json"
    a.main([str(c) for c in cfgs] + ["--csv", str(out_csv), "--json", str(out_json)])
    everything = capsys.readouterr().out + out_csv.read_text() + out_json.read_text()
    assert "<redacted>" in everything
    leaked = [v for v in values if v in everything]
    assert leaked == []


def test_cli_exit_codes(tmp_path, capsys):
    assert a.main([str(HERE / "safe-sw1.cfg")]) == 0
    assert a.main([str(HERE / "legacy-sw1.cfg")]) == 0
    assert a.main([str(HERE / "no-aaa-sw1.cfg")]) == 0
    assert a.main([str(HERE / "danger-sw1.cfg")]) == 1
    assert a.main([str(tmp_path / "missing.cfg")]) == 2
    assert a.main([]) == 2
    out_csv, out_json = tmp_path / "f.csv", tmp_path / "f.json"
    assert a.main([str(HERE / "mgmt-vrf-*.cfg"), "--csv", str(out_csv), "--json", str(out_json)]) == 1
    data = json.loads(out_json.read_text())
    assert {x["device"] for x in data} == {"mgmt-vrf-bad"}
    assert {"device", "rule", "severity", "title", "evidence", "why", "fix"} <= set(data[0])
    with out_csv.open(newline="", encoding="utf-8") as fh:
        assert [r["rule"] for r in csv.DictReader(fh)] == [x["rule"] for x in data]
    out = capsys.readouterr().out
    assert "mgmt-vrf-bad: 1 high" in out and "mgmt-vrf-fixed: 0 high, 0 medium, 0 low" in out


def test_min_severity_filters_output(tmp_path):
    out_json = tmp_path / "f.json"
    assert a.main([str(HERE / "danger-sw1.cfg"), "--min-severity", "medium", "--json", str(out_json)]) == 1
    assert {x["severity"] for x in json.loads(out_json.read_text())} == {"high", "medium"}


def test_explain_lists_every_rule(capsys):
    assert a.main(["--explain"]) == 0
    out = capsys.readouterr().out
    for rid in a.RULES:
        assert out.count(f"{rid} [") == 1
