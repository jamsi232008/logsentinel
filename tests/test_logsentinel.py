import json, os, sys, tempfile, unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logsentinel import detectors, parsers
from logsentinel.cli import main
from logsentinel.correlator import correlate
from logsentinel.models import Event
from tools.generate_sample_logs import generate

T0 = datetime(2026, 11, 16, 10, 0, 0)


def ssh_fail(i, ip="203.0.113.5", user="root", step=5):
    return Event(T0 + timedelta(seconds=i * step), "ssh", ip, "fail", user, f"fail {i}")


def web_ev(path, ip="198.51.100.9", status=200, ua="Mozilla/5.0", i=0):
    return Event(T0 + timedelta(seconds=i), "web", ip, "request", None, path,
                 {"method": "GET", "path": path, "status": status, "ua": ua})


class ParserTests(unittest.TestCase):
    def test_ssh_failed_and_accepted(self):
        lines = ["Nov 16 02:15:01 web01 sshd[1234]: Failed password for invalid user test from 203.0.113.50 port 4000 ssh2",
                 "Nov 16 02:20:01 web01 sshd[1234]: Accepted password for admin from 203.0.113.50 port 4001 ssh2",
                 "Nov 16 02:20:02 web01 cron[1]: unrelated line", "garbage"]
        ev = list(parsers.parse_ssh(lines, 2026))
        self.assertEqual([(e.action, e.user) for e in ev], [("fail", "test"), ("success", "admin")])

    def test_web_combined(self):
        line = '1.2.3.4 - - [16/Nov/2026:03:30:01 +0000] "GET /a?b=1 HTTP/1.1" 404 12 "-" "curl/8"'
        e = list(parsers.parse_web([line]))[0]
        self.assertEqual((e.ip, e.extra["status"], e.extra["path"]), ("1.2.3.4", 404, "/a?b=1"))

    def test_firewall(self):
        line = "Nov 16 02:10:01 fw01 kernel: [1.2] DROP IN=eth0 SRC=203.0.113.50 DST=10.0.0.5 PROTO=TCP DPT=443"
        e = list(parsers.parse_firewall([line], 2026))[0]
        self.assertEqual((e.ip, e.extra["dport"]), ("203.0.113.50", 443))

    def test_malformed_lines_ignored(self):
        self.assertEqual(list(parsers.parse_web(["not a log line"])), [])
        self.assertEqual(list(parsers.parse_firewall(["nothing here"], 2026)), [])


class DetectorTests(unittest.TestCase):
    cfg = detectors.DEFAULTS

    def test_bruteforce_positive_and_negative(self):
        self.assertEqual(detectors.ssh_bruteforce([ssh_fail(i) for i in range(5)], self.cfg)[0].rule, "ssh_bruteforce")
        self.assertEqual(detectors.ssh_bruteforce([ssh_fail(i) for i in range(4)], self.cfg), [])

    def test_bruteforce_respects_window(self):  # 5 failures but spread 10 min apart
        self.assertEqual(detectors.ssh_bruteforce([ssh_fail(i, step=600) for i in range(5)], self.cfg), [])

    def test_user_enumeration(self):
        ev = [ssh_fail(i, user=f"u{i}") for i in range(6)]
        self.assertEqual(detectors.user_enumeration(ev, self.cfg)[0].count, 6)
        self.assertEqual(detectors.user_enumeration([ssh_fail(i) for i in range(30)], self.cfg), [])

    def test_login_after_bruteforce(self):
        ev = [ssh_fail(i) for i in range(6)] + [Event(T0 + timedelta(seconds=40), "ssh", "203.0.113.5", "success", "root")]
        a = detectors.compromise_after_failures(ev, self.cfg)
        self.assertEqual((a[0].rule, a[0].severity), ("login_after_bruteforce", "CRITICAL"))

    def test_success_without_failures_is_not_flagged(self):
        ev = [Event(T0, "ssh", "192.0.2.10", "success", "alice")]
        self.assertEqual(detectors.compromise_after_failures(ev, self.cfg), [])

    def test_port_scan(self):
        ev = [Event(T0 + timedelta(seconds=i), "firewall", "203.0.113.9", "drop", extra={"dport": 20 + i}) for i in range(12)]
        self.assertEqual(detectors.port_scan(ev, self.cfg)[0].count, 12)
        same_port = [Event(T0 + timedelta(seconds=i), "firewall", "203.0.113.9", "drop", extra={"dport": 22}) for i in range(50)]
        self.assertEqual(detectors.port_scan(same_port, self.cfg), [])

    def test_web_signatures(self):
        cases = {"sql_injection": "/p?id=1%20UNION%20SELECT%20a,b", "xss": "/s?q=%3Cscript%3E",
                 "path_traversal": "/d?f=../../etc/passwd", "command_injection": "/ping?h=1;id"}
        for rule, path in cases.items():
            rules = {a.rule for a in detectors.web_attacks([web_ev(path)], self.cfg)}
            self.assertIn(rule, rules, rule)

    def test_benign_web_not_flagged(self):
        ev = [web_ev(p) for p in ("/", "/products?id=7", "/about", "/search?q=union+station")]
        self.assertEqual(detectors.web_attacks(ev, self.cfg), [])

    def test_scanner_ua(self):
        self.assertEqual(detectors.web_attacks([web_ev("/", ua="Nikto/2.5")], self.cfg)[0].rule, "scanner_user_agent")

    def test_dir_enumeration(self):
        ev = [web_ev(f"/x{i}", status=404, i=i) for i in range(16)]
        self.assertEqual(detectors.dir_enumeration(ev, self.cfg)[0].rule, "dir_enumeration")
        self.assertEqual(detectors.dir_enumeration(ev[:5], self.cfg), [])

    def test_allowlist(self):
        ev = [ssh_fail(i) for i in range(10)]
        self.assertEqual(detectors.run_all(ev, allowlist=["203.0.113.5"]), [])


class CorrelatorTests(unittest.TestCase):
    def test_multi_stage_escalates_to_critical(self):
        ev = [ssh_fail(i, user=f"u{i}") for i in range(6)] + \
             [Event(T0 + timedelta(seconds=i), "firewall", "203.0.113.5", "drop", extra={"dport": 20 + i}) for i in range(12)]
        inc = correlate(detectors.run_all(ev))
        self.assertEqual(inc[0]["severity"], "CRITICAL")
        self.assertTrue(inc[0]["multi_stage"])

    def test_single_low_signal_stays_medium(self):
        inc = correlate(detectors.run_all([web_ev("/", ua="Nikto/2.5", ip="198.51.100.1")]))
        self.assertEqual(inc[0]["severity"], "MEDIUM")


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.data = os.path.join(cls.tmp.name, "data")
        generate(cls.data)
        cls.out = os.path.join(cls.tmp.name, "out")
        cls.rc = main(["--ssh", f"{cls.data}/auth.log", "--web", f"{cls.data}/access.log",
                       "--fw", f"{cls.data}/firewall.log", "--year", "2026", "--out", cls.out])
        with open(os.path.join(cls.out, "report.json")) as f:
            cls.report = json.load(f)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_exit_code_signals_critical(self):
        self.assertEqual(self.rc, 2)

    def test_expected_attackers_found(self):
        ips = {i["ip"]: i for i in self.report["incidents"]}
        self.assertEqual(ips["203.0.113.50"]["severity"], "CRITICAL")
        self.assertTrue(ips["203.0.113.50"]["multi_stage"])
        self.assertIn("sql_injection", {a["rule"] for a in ips["198.51.100.77"]["alerts"]})
        self.assertIn("dir_enumeration", {a["rule"] for a in ips["198.51.100.23"]["alerts"]})

    def test_no_false_positives_on_benign_hosts(self):
        flagged = {i["ip"] for i in self.report["incidents"]}
        self.assertFalse(any(ip.startswith("192.0.2.") for ip in flagged))
        self.assertEqual(len(flagged), 3)

    def test_outputs_written_and_html_escaped(self):
        for f in ("report.html", "report.json", "iocs.csv", "blocklist.txt"):
            self.assertTrue(os.path.exists(os.path.join(self.out, f)), f)

    def test_blocklist_contains_attackers_only(self):
        with open(os.path.join(self.out, "blocklist.txt")) as f:
            bl = f.read()
        self.assertIn("203.0.113.50", bl)
        self.assertNotIn("192.0.2.", bl)


class ReportSecurityTests(unittest.TestCase):
    def test_attacker_controlled_fields_are_escaped_in_html(self):
        """Log injection: a hostile User-Agent must not become live markup in the report."""
        evil = "Nikto <script>alert(1)</script>"
        incidents = correlate(detectors.run_all([web_ev("/", ua=evil, ip="198.51.100.66")]))
        with tempfile.TemporaryDirectory() as d:
            from logsentinel.report import write_reports
            write_reports(incidents, {"alerts": 1}, d)
            with open(os.path.join(d, "report.html")) as f:
                html = f.read()
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
