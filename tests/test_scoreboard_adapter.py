"""Tests for ConfigurableScoreboardAdapter and schema normalization."""
import json
import time
import unittest
from unittest.mock import MagicMock, patch

import requests

from agent.scoreboard.adapter import ConfigurableScoreboardAdapter
from agent.scoreboard.base import NormalizedScoreboardState
from agent.scoreboard.config_parser import ScoreboardSchemaConfig, resolve_json_path


class TestScoreboardAdapter(unittest.TestCase):
    def test_resolve_json_path(self):
        data = {
            "game": {
                "round": {"number": 3, "state": "active"},
                "teams": [
                    {"name": "red", "score": 100},
                    {"name": "blue", "score": 250},
                ],
            }
        }
        self.assertEqual(resolve_json_path(data, "game.round.number"), 3)
        self.assertEqual(resolve_json_path(data, "game.round.state"), "active")
        self.assertEqual(resolve_json_path(data, "game.teams.1.score"), 250)
        self.assertIsNone(resolve_json_path(data, "game.invalid.path"))
        self.assertEqual(resolve_json_path(data, "game.teams.99.score", default=0), 0)

    def test_default_schema_parsing(self):
        adapter = ConfigurableScoreboardAdapter(url="http://mock-scoreboard/api")
        payload = {
            "timestamp": time.time(),
            "our_score": 1250.0,
            "rank": 2,
            "round_state": "active",
            "our_services": [
                {"host": "10.0.1.5", "port": 80, "up": True, "note": "healthy"},
                {"host": "10.0.1.5", "port": 443, "up": False, "note": "connection refused"},
            ],
            "competitor_scores": {"team2": 1500.0, "team3": 900.0},
        }

        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = payload
        mock_session.get.return_value = mock_resp
        adapter.session = mock_session

        state = adapter.get_state()
        self.assertTrue(state.is_valid)
        self.assertFalse(state.is_stale)
        self.assertIsNone(state.error)
        self.assertEqual(state.own_score, 1250.0)
        self.assertEqual(state.rank, 2)
        self.assertEqual(len(state.service_status), 2)
        self.assertTrue(state.service_status[0].up)
        self.assertFalse(state.service_status[1].up)
        self.assertEqual(state.opponent_scores["team2"], 1500.0)

    def test_score_delta_tracking(self):
        adapter = ConfigurableScoreboardAdapter(url="http://mock-scoreboard/api")
        mock_session = MagicMock()
        adapter.session = mock_session

        mock_resp1 = MagicMock(status_code=200, json=lambda: {"our_score": 1000.0})
        mock_resp2 = MagicMock(status_code=200, json=lambda: {"our_score": 1150.0})
        mock_resp3 = MagicMock(status_code=200, json=lambda: {"our_score": 1100.0})
        mock_session.get.side_effect = [mock_resp1, mock_resp2, mock_resp3]

        s1 = adapter.get_state()
        self.assertEqual(s1.score_delta, 0.0)

        s2 = adapter.get_state()
        self.assertEqual(s2.score_delta, 150.0)

        s3 = adapter.get_state()
        self.assertEqual(s3.score_delta, -50.0)

    def test_custom_nested_schema(self):
        schema = ScoreboardSchemaConfig(
            score_path="data.team_stats.points",
            rank_path="data.team_stats.standing",
            round_state_path="data.match.status",
            services_path="data.monitored_endpoints",
            service_host_path="endpoint.ip",
            service_port_path="endpoint.port",
            service_up_path="health.alive",
            service_note_path="health.msg",
            competitors_path="data.leaderboard",
        )
        adapter = ConfigurableScoreboardAdapter(url="http://custom-scoreboard/api", schema_config=schema)
        mock_session = MagicMock()
        adapter.session = mock_session

        payload = {
            "data": {
                "match": {"status": "in_progress"},
                "team_stats": {"points": 4200, "standing": 1},
                "monitored_endpoints": [
                    {
                        "endpoint": {"ip": "10.0.1.5", "port": "8080"},
                        "health": {"alive": True, "msg": "ok"},
                    }
                ],
                "leaderboard": {"rival_team": 3800},
            }
        }
        mock_session.get.return_value = MagicMock(status_code=200, json=lambda: payload)

        state = adapter.get_state()
        self.assertTrue(state.is_valid)
        self.assertEqual(state.own_score, 4200.0)
        self.assertEqual(state.rank, 1)
        self.assertEqual(state.round_state, "in_progress")
        self.assertEqual(len(state.service_status), 1)
        self.assertEqual(state.service_status[0].port, 8080)
        self.assertEqual(state.service_status[0].note, "ok")
        self.assertEqual(state.opponent_scores["rival_team"], 3800.0)

    def test_teams_list_schema(self):
        schema = ScoreboardSchemaConfig(
            teams_list_path="scoreboard.teams",
            team_name="CyberWolves",
            team_name_key="team",
            team_score_key="score",
            team_rank_key="pos",
        )
        adapter = ConfigurableScoreboardAdapter(url="http://ctf/api", schema_config=schema)
        payload = {
            "scoreboard": {
                "teams": [
                    {"team": "Hax0rs", "score": 900, "pos": 1},
                    {"team": "CyberWolves", "score": 850, "pos": 2},
                    {"team": "Pwners", "score": 700, "pos": 3},
                ]
            }
        }
        adapter.session = MagicMock(get=lambda *a, **k: MagicMock(status_code=200, json=lambda: payload))
        state = adapter.get_state()
        self.assertEqual(state.own_score, 850.0)
        self.assertEqual(state.rank, 2)
        self.assertIn("Hax0rs", state.opponent_scores)
        self.assertIn("Pwners", state.opponent_scores)

    def test_http_error_handling(self):
        adapter = ConfigurableScoreboardAdapter(url="http://mock/api")
        adapter.session = MagicMock(get=lambda *a, **k: MagicMock(status_code=500, text="Internal Server Error"))
        state = adapter.get_state()
        self.assertFalse(state.is_valid)
        self.assertTrue(state.has_error)
        self.assertIn("HTTP 500", state.error)

    def test_timeout_handling(self):
        adapter = ConfigurableScoreboardAdapter(url="http://mock/api")
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.Timeout("Connection timed out")
        adapter.session = mock_session

        state = adapter.get_state()
        self.assertFalse(state.is_valid)
        self.assertTrue(state.has_error)
        self.assertIn("timed out", state.error.lower())

    def test_malformed_json_handling(self):
        adapter = ConfigurableScoreboardAdapter(url="http://mock/api")
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.side_effect = json.JSONDecodeError("Expecting value", "bad json", 0)
        adapter.session = MagicMock(get=lambda *a, **k: mock_resp)

        state = adapter.get_state()
        self.assertFalse(state.is_valid)
        self.assertIn("Malformed JSON", state.error)

    def test_malformed_root_array(self):
        adapter = ConfigurableScoreboardAdapter(url="http://mock/api")
        mock_resp = MagicMock(status_code=200, json=lambda: ["not", "a", "dict"])
        adapter.session = MagicMock(get=lambda *a, **k: mock_resp)

        state = adapter.get_state()
        self.assertFalse(state.is_valid)
        self.assertIn("Malformed payload", state.error)

    def test_stale_data_detection(self):
        schema = ScoreboardSchemaConfig(stale_threshold_seconds=30.0)
        adapter = ConfigurableScoreboardAdapter(url="http://mock/api", schema_config=schema)
        # 100 seconds in the past
        old_time = time.time() - 100.0
        payload = {"timestamp": old_time, "our_score": 500.0}
        adapter.session = MagicMock(get=lambda *a, **k: MagicMock(status_code=200, json=lambda: payload))

        state = adapter.get_state()
        self.assertTrue(state.is_stale)
        self.assertFalse(state.is_valid)
        self.assertIn("stale", state.error.lower())

    def test_to_telemetry_conversion(self):
        adapter = ConfigurableScoreboardAdapter(url="http://mock/api")
        payload = {
            "timestamp": time.time(),
            "our_score": 100.0,
            "rank": 5,
            "our_services": [{"host": "10.0.1.5", "port": 80, "up": True}],
        }
        adapter.session = MagicMock(get=lambda *a, **k: MagicMock(status_code=200, json=lambda: payload))
        state = adapter.get_state()
        telemetry = adapter.to_telemetry(state)

        self.assertEqual(telemetry.our_score, 100.0)
        self.assertEqual(telemetry.rank, 5)
        self.assertEqual(len(telemetry.our_services), 1)
        self.assertTrue(telemetry.our_services[0].up)


if __name__ == "__main__":
    unittest.main()
