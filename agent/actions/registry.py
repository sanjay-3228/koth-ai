"""Action Registry mapping validated decision types to registered executable action handlers."""
from typing import Dict, Optional, Type

from .base import BaseAction
from .defense_actions import BlockSourceAction, RateLimitPortAction, RestartServiceAction
from .attack_actions import ExploitPluginAction, ReconScanAction
from .hold_action import HoldAction
from ..logger import get_logger

logger = get_logger(__name__)


class ActionRegistry:
    def __init__(self):
        self._actions: Dict[str, BaseAction] = {}
        self._register_default_actions()

    def _register_default_actions(self):
        # Register standard defensive actions
        self.register(RestartServiceAction())
        self.register(RateLimitPortAction())
        self.register(BlockSourceAction())

        # Register standard offensive / recon actions
        self.register(ReconScanAction())
        self.register(ExploitPluginAction())

        # Register safe hold action
        self.register(HoldAction())

    def register(self, action: BaseAction) -> None:
        self._actions[action.action_name] = action
        logger.debug("Registered action '%s' (%s)", action.action_name, action.action_type)

    @property
    def actions(self) -> Dict[str, BaseAction]:
        return dict(self._actions)

    @property
    def catalog(self) -> Dict[str, BaseAction]:
        return dict(self._actions)

    def get_action(self, action_name: str) -> Optional[BaseAction]:
        action = self._actions.get(action_name)
        if action and action.action_name != "hold":
            from ..config import config
            if not config.is_action_allowed(action.action_name):
                logger.warning(
                    f"[SECURITY] Action '{action.action_name}' requested but forbidden by Config.allowed_actions allowlist."
                )
                return None
        return action

    def resolve(
        self,
        action_type: str,
        target: str = "",
        details: str = "",
        fallback_to_hold: bool = True,
        config: Optional[object] = None,
    ) -> BaseAction:
        """Resolve a validated action_type to its concrete registered handler."""
        if action_type == "defend":
            # If target has a port, restart service; if rate_limit indicated, rate limit
            if "rate_limit" in details or "tamper" in details:
                resolved = self._actions.get("rate_limit_port", self._actions["restart_service"])
            else:
                resolved = self._actions.get("restart_service", self._actions["hold"])

        elif action_type == "recon":
            resolved = self._actions.get("recon_scan", self._actions["hold"])

        elif action_type == "attack":
            resolved = self._actions.get("exploit_plugin", self._actions["hold"])

        else:
            resolved = self._actions.get("hold", HoldAction())

        # Enforce Config.allowed_actions allowlist on the resolved concrete action
        if resolved.action_name != "hold" and fallback_to_hold:
            active_config = config
            if active_config is None:
                from ..config import config as global_config
                active_config = global_config
            if not active_config.is_action_allowed(resolved.action_name):
                logger.warning(
                    f"[SECURITY] Resolved action '{resolved.action_name}' is forbidden by Config.allowed_actions "
                    f"({active_config.allowed_actions}). Falling back to safe hold."
                )
                return self._actions.get("hold", HoldAction())

        return resolved


action_registry = ActionRegistry()
