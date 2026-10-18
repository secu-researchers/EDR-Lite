import json
import tempfile
import unittest
from pathlib import Path

import relay


def line(**kw):
    ev = {"v": 1, "sid": "run-1", "seq": 1, "ts_ms": 1, "kind": "net"}
    ev.update(kw)
    return json.dumps(ev).encode()


class ValidateTests(unittest.TestCase):
    def test_accepts_valid_batch(self):
        body = line(seq=1) + b"\n" + line(seq=2) + b"\n"
        self.assertEqual(len(relay.validate_batch("run-1", body)), 2)

    def test_rejects_sid_mismatch(self):
        with self.assertRaises(ValueError):
            relay.validate_batch("other", line())

    def test_rejects_unknown_kind_and_bad_types(self):
        for bad in (line(kind="evil"), line(seq="1"), line(seq=0), line(seq=relay.MAX_SEQ + 1),
                    b"not json", b"[1]", b""):
            with self.assertRaises(ValueError):
                relay.validate_batch("run-1", bad)

    def test_rejects_oversized_line(self):
        with self.assertRaises(ValueError):
            relay.validate_batch("run-1", line(cmdline="x" * relay.MAX_LINE_BYTES))


class SeqSetTests(unittest.TestCase):
    def test_counts_unique_only(self):
        s = relay.SeqSet()
        self.assertTrue(s.add(5))
        self.assertFalse(s.add(5))
        self.assertTrue(s.add(100000))
        self.assertEqual(s.count, 2)


class TrackerTests(unittest.TestCase):
    def hb(self, seq, **kw):
        ev = {"v": 1, "sid": "s", "seq": seq, "ts_ms": 1, "kind": "heartbeat",
              "dropped_queue": 0, "dropped_send": 0, "etw_alive": True}
        ev.update(kw)
        return ev

    def ev(self, seq, kind="net"):
        return {"v": 1, "sid": "s", "seq": seq, "ts_ms": 1, "kind": kind}

    def test_no_alert_when_complete(self):
        t = relay.Tracker(10)
        batch = [self.ev(1), self.ev(2), self.hb(3)]
        self.assertEqual(t.observe("s", batch, 0.0), [])

    def test_drop_counters_explain_gap(self):
        t = relay.Tracker(10)
        batch = [self.ev(1), self.ev(3), self.hb(4, dropped_queue=1)]
        self.assertEqual(t.observe("s", batch, 0.0), [])

    def test_unexplained_gap_alerts_on_second_heartbeat(self):
        t = relay.Tracker(10)
        self.assertEqual(t.observe("s", [self.ev(1), self.hb(3)], 0.0), [])
        alerts = t.observe("s", [self.hb(4)], 10.0)
        self.assertEqual([a["reason"] for a in alerts], ["seq_gap"])

    def test_etw_not_alive_alert(self):
        t = relay.Tracker(10)
        alerts = t.observe("s", [self.hb(1, etw_alive=False)], 0.0)
        self.assertEqual([a["reason"] for a in alerts], ["etw_not_alive"])

    def test_silence_alert_once_and_not_after_stop(self):
        t = relay.Tracker(10)
        t.observe("s", [self.hb(1)], 0.0)
        self.assertEqual(t.check_silence(20.0), [])
        self.assertEqual([a["reason"] for a in t.check_silence(31.0)], ["heartbeat_silence"])
        self.assertEqual(t.check_silence(60.0), [])
        t2 = relay.Tracker(10)
        t2.observe("s", [self.hb(1), self.ev(2, "agent_stop")], 0.0)
        self.assertEqual(t2.check_silence(100.0), [])


class EntryAndSpoolTests(unittest.TestCase):
    def test_entry_fields(self):
        e = relay.make_entry({"v": 1, "sid": "s", "seq": 7, "ts_ms": 1, "kind": "etw_stopped"}, 123)
        self.assertEqual(e["insert_id"], "s-7")
        self.assertEqual(e["severity"], "ERROR")
        self.assertEqual(e["payload"]["recv_ts_ms"], 123)
        self.assertEqual(e["labels"], {"sid": "s", "kind": "etw_stopped"})

    def test_spool_order_limit_and_remove(self):
        with tempfile.TemporaryDirectory() as d:
            sp = relay.Spool(d, max_files=2)
            e = relay.make_entry({"v": 1, "sid": "s", "seq": 1, "ts_ms": 1, "kind": "net"}, 1)
            self.assertTrue(sp.put([e]))
            self.assertTrue(sp.put([e, e]))
            self.assertFalse(sp.put([e]))
            first = sp.oldest()
            self.assertEqual(len(Path(first).read_text().splitlines()), 1)
            sp.remove(first)
            self.assertTrue(sp.put([e]))


class AllowedCNTests(unittest.TestCase):
    def test_reload_on_change(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "cn.txt"
            p.write_text("# c\nrun-1\n", encoding="utf-8")
            a = relay.AllowedCN(p)
            self.assertTrue(a.contains("run-1"))
            self.assertFalse(a.contains("run-2"))
            p.write_text("run-2\n", encoding="utf-8")
            import os
            st = p.stat()
            os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
            self.assertFalse(a.contains("run-1"))
            self.assertTrue(a.contains("run-2"))


if __name__ == "__main__":
    unittest.main()
