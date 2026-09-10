"""Local web dashboard for koth-agent.

Exposes a web interface and JSON API showing:
  - Current score and rank
  - Monitored services status
  - Competitor scores
  - Last 20 decisions/actions from SQLite persistence
"""
import os
import time
from typing import Any, Optional

from flask import Flask, jsonify, render_template

from .config import config
from .db import DatabaseManager, db
from .logger import get_logger

logger = get_logger(__name__)


def create_app(
    db_manager: Optional[DatabaseManager] = None,
    coordinator: Optional[Any] = None,
) -> Flask:
    template_folder = os.path.join(os.path.dirname(__file__), "templates")
    app = Flask(__name__, template_folder=template_folder)
    database = db_manager or db

    if coordinator is not None:
        from .swarm.coordinator import create_coordinator_blueprint
        app.register_blueprint(create_coordinator_blueprint(coordinator))

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/status")
    def api_status():
        from .model_router import router

        latest_telemetry = database.get_latest_telemetry() or {
            "timestamp": time.time(),
            "our_score": 0.0,
            "rank": None,
            "our_services": [],
            "competitor_scores": {},
            "raw": {},
        }
        recent_actions = database.get_recent_actions(limit=20)
        router_summary = router.metrics.get_summary()
        empirical_stats = database.get_empirical_success_stats(limit=50)

        # Reflect most recently executed action's model and confidence if present
        if recent_actions:
            latest = recent_actions[0]
            if latest.get("model_used"):
                router_summary["current_model"] = latest["model_used"]
            if latest.get("confidence") is not None:
                router_summary["latest_confidence"] = round(float(latest["confidence"]), 2)

        swarm_status = coordinator.get_swarm_status() if coordinator else None

        return jsonify(
            {
                "telemetry": latest_telemetry,
                "recent_actions": recent_actions,
                "server_time": time.time(),
                "config": {
                    "team_id": config.team_id,
                    "agent_id": config.agent_id,
                    "primary_model": config.nvidia_fast_model,
                    "reasoning_model": config.nvidia_reasoning_model,
                    "confidence_threshold": config.nvidia_confidence_threshold,
                    "dry_run": config.dry_run,
                    "tick_interval": config.tick_interval_seconds,
                    "model": config.nvidia_fast_model,
                    "nvidia_base_url": config.nvidia_base_url,
                    "swarm_enabled": config.swarm_enabled,
                },
                "router_metrics": router_summary,
                "empirical_stats": empirical_stats,
                "swarm": swarm_status,
            }
        )

    return app


def run_dashboard(
    host: Optional[str] = None,
    port: Optional[int] = None,
    debug: bool = False,
    db_manager: Optional[DatabaseManager] = None,
    coordinator: Optional[Any] = None,
):
    app = create_app(db_manager=db_manager, coordinator=coordinator)
    h = host or config.dashboard_host
    p = port or config.dashboard_port
    logger.info("Starting koth-agent dashboard on http://%s:%d", h, p)
    app.run(host=h, port=p, debug=debug)


if __name__ == "__main__":
    run_dashboard()
