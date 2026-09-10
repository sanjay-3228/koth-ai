"""Loads plugins from /plugins and securely dispatches based on recon fingerprint and allowlists."""
import importlib.util
import inspect
import os
from typing import List, Optional

from .plugin_interface import ExploitPlugin, ExploitResult
from .recon import HostFingerprint
from ..config import Config, config
from ..logger import get_logger

logger = get_logger(__name__)

PLUGINS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "plugins")


class PluginDispatcher:
    def __init__(self, plugins_dir: str = PLUGINS_DIR, allowed_plugins: Optional[List[str]] = None):
        self.plugins_dir = plugins_dir
        self.allowed_plugins = allowed_plugins if allowed_plugins is not None else config.allowed_plugins
        self.plugins: List[ExploitPlugin] = self._load_plugins()

    def _load_plugins(self) -> List[ExploitPlugin]:
        plugins = []
        if not os.path.isdir(self.plugins_dir):
            return plugins

        for fname in os.listdir(self.plugins_dir):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            path = os.path.join(self.plugins_dir, fname)
            try:
                spec = importlib.util.spec_from_file_location(fname[:-3], path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for _, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, ExploitPlugin) and obj is not ExploitPlugin:
                        instance = obj()
                        # Explicit allowlist is mandatory: empty ALLOWED_PLUGINS means
                        # no filesystem-discovered exploit plugins are executable.
                        if instance.name not in self.allowed_plugins:
                            logger.warning(
                                "[SECURITY] Discovered plugin '%s' not in ALLOWED_PLUGINS allowlist; skipping.",
                                instance.name,
                            )
                            continue
                        plugins.append(instance)
            except Exception as exc:
                logger.error("Failed loading plugin from %s: %s", fname, exc)

        return plugins

    def register(self, plugin: ExploitPlugin) -> None:
        """Register a plugin instance directly."""
        self.plugins.append(plugin)

    def select_plugin(self, fingerprint: HostFingerprint) -> Optional[ExploitPlugin]:
        for service_str in fingerprint.services.values():
            for plugin in self.plugins:
                if plugin.matches_service and plugin.matches_service in service_str:
                    # Enforce allowlist check at selection time as well.
                    if plugin.name not in self.allowed_plugins:
                        logger.warning(
                            "[SECURITY] Plugin '%s' matched but is not in ALLOWED_PLUGINS allowlist.",
                            plugin.name,
                        )
                        continue
                    return plugin
        return None

    def dispatch(
        self,
        fingerprint: HostFingerprint,
        target_port: int,
        context: dict,
        cfg: Optional[Config] = None,
    ) -> Optional[ExploitResult]:
        active_config = cfg or config
        # Enforce target authorization unconditionally against authorized TARGET_HOSTS.
        if not active_config.is_target_host(fingerprint.host):
            logger.error(
                "[SECURITY VIOLATION] Attempted exploit dispatch against unauthorized target host '%s'. Aborted.",
                fingerprint.host,
            )
            return None

        plugin = self.select_plugin(fingerprint)
        if plugin is None:
            return None

        # Sanitize context before passing to plugin (strip credentials / env vars)
        sanitized_context = {
            "host": str(fingerprint.host),
            "port": int(target_port),
            "open_ports": list(fingerprint.open_ports),
            "services": dict(fingerprint.services),
        }

        logger.info(
            "Executing authorized plugin '%s' against target %s:%d",
            plugin.name,
            fingerprint.host,
            target_port,
        )
        return plugin.run(fingerprint.host, target_port, sanitized_context)
