import unittest
from datetime import datetime, timedelta, timezone

import main


def ev(**kw):
    base = {"v": 1, "sid": "run-1", "seq": 1, "ts_ms": 1000, "kind": "proc_start", "pid": 4}
    base.update(kw)
    return base


def hb(**kw):
    base = {
        "v": 1, "sid": "run-1", "seq": 10, "ts_ms": 1000, "kind": "heartbeat",
        "dropped_queue": 0, "dropped_send": 0, "etw_alive": True, "etw_restarts": 0,
    }
    base.update(kw)
    return base


class ValidateTests(unittest.TestCase):
    def test_accepts_valid_events(self):
        fields, reason = main.validate_event(ev())
        self.assertIsNone(reason)
        self.assertEqual(fields["sid"], "run-1")
        self.assertEqual(fields["pid"], 4)
        self.assertIn('"kind":"proc_start"', fields["payload"])
        fields, reason = main.validate_event(hb())
        self.assertIsNone(reason)
        self.assertIs(fields["etw_alive"], True)

    def test_rejects_bad_fields(self):
        cases = {
            "not_object": [1],
            "unknown_kind": ev(kind="evil"),
            "bad_sid": ev(sid="has space"),
            "bad_seq": ev(seq=0),
            "bad_ts": ev(ts_ms=-1),
            "bad_version": ev(v=2),
            "bad_pid": ev(pid=-5),
            "bad_heartbeat": hb(etw_alive="yes"),
        }
        for expected, payload in cases.items():
            fields, reason = main.validate_event(payload)
            self.assertIsNone(fields, expected)
            self.assertEqual(reason, expected)

    def test_rejects_wrong_types_and_bools(self):
        for payload in (ev(seq="1"), ev(seq=True), ev(v=True), ev(sid="a" * 65), hb(dropped_send=-1)):
            fields, _ = main.validate_event(payload)
            self.assertIsNone(fields)

    def test_rejects_oversized_payload(self):
        fields, reason = main.validate_event(ev(cmdline="x" * (main.MAX_PAYLOAD_BYTES + 1)))
        self.assertIsNone(fields)
        self.assertEqual(reason, "too_large")


class EntryTests(unittest.TestCase):
    def test_process_entry_builds_row(self):
        entry = {
            "jsonPayload": ev(),
            "severity": "WARNING",
            "insertId": "run-1-1",
            "receiveTimestamp": "2026-10-19T01:02:03.123456789Z",
        }
        row, insert_id, reason = main.process_entry(entry)
        self.assertIsNone(reason)
        self.assertEqual(insert_id, "run-1-1")
        self.assertEqual(row["severity"], "WARNING")
        self.assertEqual(row["recv_time"], "2026-10-19T01:02:03.123456+00:00")

    def test_unknown_severity_and_missing_time_are_defaulted(self):
        row, insert_id, _ = main.process_entry({"jsonPayload": ev(), "severity": "BOGUS"})
        self.assertEqual(row["severity"], "DEFAULT")
        self.assertIsNone(insert_id)
        self.assertIn("recv_time", row)

    def test_invalid_entry_returns_reason(self):
        self.assertEqual(main.process_entry("x")[2], "bad_entry")
        self.assertEqual(main.process_entry({"jsonPayload": ev(kind="evil")})[2], "unknown_kind")

    def test_parse_rfc3339(self):
        self.assertEqual(
            main.parse_rfc3339("2026-10-19T01:02:03Z"),
            datetime(2026, 10, 19, 1, 2, 3, tzinfo=timezone.utc),
        )
        self.assertIsNone(main.parse_rfc3339("2026-10-19 01:02:03"))
        self.assertIsNone(main.parse_rfc3339(None))


class RealtimeAlertTests(unittest.TestCase):
    def test_conditions(self):
        row = main.validate_event(ev(kind="etw_stopped"))[0]
        self.assertEqual([a[0] for a in main.realtime_alerts(row)], ["etw_stopped"])
        row = main.validate_event(hb(etw_alive=False))[0]
        self.assertEqual([a[0] for a in main.realtime_alerts(row)], ["etw_not_alive"])
        row = main.validate_event(hb())[0]
        self.assertEqual(main.realtime_alerts(row), [])


class SessionTests(unittest.TestCase):
    now = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)

    def session(self, **kw):
        base = {
            "last_start": self.now - timedelta(minutes=10),
            "last_stop": None,
            "last_hb": self.now - timedelta(seconds=5),
            "hb_seq": 10,
            "dropped_queue": 0,
            "dropped_send": 0,
            "received_le_hb": 10,
        }
        base.update(kw)
        return base

    def reasons(self, s):
        return [a[0] for a in main.evaluate_session(s, self.now, 10)]

    def test_healthy_session_has_no_alerts(self):
        self.assertEqual(self.reasons(self.session()), [])

    def test_heartbeat_silence(self):
        s = self.session(last_hb=self.now - timedelta(seconds=31))
        self.assertIn("heartbeat_silence", self.reasons(s))
        s = self.session(last_hb=self.now - timedelta(seconds=29))
        self.assertNotIn("heartbeat_silence", self.reasons(s))

    def test_silence_without_any_heartbeat_counts_from_start(self):
        s = self.session(last_hb=None, hb_seq=None, received_le_hb=None,
                         last_start=self.now - timedelta(seconds=40))
        self.assertEqual(self.reasons(s), ["heartbeat_silence"])

    def test_closed_session_is_ignored(self):
        s = self.session(last_hb=self.now - timedelta(minutes=6),
                         last_stop=self.now - timedelta(minutes=5))
        self.assertEqual(self.reasons(s), [])

    def test_restart_after_stop_is_active_again(self):
        s = self.session(last_stop=self.now - timedelta(minutes=20),
                         last_hb=self.now - timedelta(minutes=5))
        self.assertIn("heartbeat_silence", self.reasons(s))

    def test_seq_gap_needs_grace_and_is_explained_by_drops(self):
        # 마지막 heartbeat 가 20초 전: 유예(60초) 이내라 누락이 있어도 아직 알리지 않는다
        early = self.session(received_le_hb=8, last_hb=self.now - timedelta(seconds=20))
        self.assertEqual(self.reasons(early), [])
        # 65초 뒤에 판정하면 유예가 지나 2건 누락으로 알린다 (heartbeat 공백 기준은 크게 잡아 분리)
        late = self.session(received_le_hb=8, last_hb=self.now - timedelta(seconds=25))
        result = main.evaluate_session(late, self.now + timedelta(seconds=40), 100)
        self.assertEqual([a[0] for a in result], ["seq_gap"])
        # 드롭 카운터로 설명되는 누락은 알리지 않는다
        explained = self.session(received_le_hb=8, dropped_queue=1, dropped_send=1)
        result = main.evaluate_session(explained, self.now + timedelta(seconds=60), 100)
        self.assertEqual(result, [])


class FormatTests(unittest.TestCase):
    def test_alert_text_has_no_mentions_or_markdown(self):
        text = main.format_alert("run-1", "invalid_event", "@everyone `x` *y* <@1>")
        self.assertNotIn("@", text)
        self.assertNotIn("`", text)
        self.assertIn("sid=run-1", text)
        self.assertIn("invalid_event", text)

    def test_missing_sid_is_unknown(self):
        self.assertIn("sid=unknown", main.format_alert(None, "invalid_event", "x"))


if __name__ == "__main__":
    unittest.main()
