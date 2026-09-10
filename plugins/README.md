# Plugins

This directory is intentionally empty. Drop one Python file per exploit
here, each implementing `ExploitPlugin` from
`agent/attack/plugin_interface.py`.

The dispatcher auto-loads every `.py` file in this folder at startup and
matches plugins to targets based on `matches_service` against the recon
fingerprint (e.g. "vsftpd 2.3.4").

See the docstring in `agent/attack/plugin_interface.py` for the exact
interface and a skeleton example.
