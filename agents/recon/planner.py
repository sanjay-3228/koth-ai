"""Scientific reasoning and planning engine for safe reconnaissance.

Enforces:
- Observation -> Hypothesis -> Safe Test -> Result -> Conclusion workflow.
- Pure reasoning/planning; no shell execution.
- Avoids repeating known failed approaches.
- Reasons purely about observed facts (status, headers, robots.txt, paths).
- No speculative vulnerability assumptions.
"""

import re
from typing import Any, Dict, List, Optional, Set

from core.schemas import (
    ConclusionStatus,
    Hypothesis,
    HypothesisStatus,
    Observation,
    SafeTest,
    TestResult,
    TestStatus,
)
from core.session import Session


class ReconPlanner:
    """Deductive planning and reasoning engine for authorized reconnaissance."""

    def analyze_observations(self, session: Session) -> Dict[str, Any]:
        """Extract verified facts from session observations and failed approaches."""
        known_paths: Set[str] = set()
        disallowed_paths: Set[str] = set()
        observed_headers: Dict[str, str] = {}
        root_observed = False
        robots_observed = False
        target_responsive = False

        for obs in session.observations:
            attrs = obs.attributes or {}
            path = attrs.get("path")
            if path:
                known_paths.add(path)
                if path == "/":
                    root_observed = True
                elif path == "/robots.txt":
                    robots_observed = True

            if attrs.get("status_code") and int(attrs.get("status_code")) < 500:
                target_responsive = True

            for p in attrs.get("disallowed_paths", []):
                if isinstance(p, str) and p.startswith("/"):
                    disallowed_paths.add(p)

            headers = attrs.get("headers", {})
            if isinstance(headers, dict):
                observed_headers.update(headers)

        # Also extract failed paths from failed approaches
        failed_paths: Set[str] = set()
        for fa in session.failed_approaches:
            if fa.tool == "http_probe":
                p = fa.parameters.get("path")
                if p:
                    failed_paths.add(p)

        return {
            "known_paths": known_paths,
            "failed_paths": failed_paths,
            "disallowed_paths": disallowed_paths,
            "observed_headers": observed_headers,
            "root_observed": root_observed,
            "robots_observed": robots_observed,
            "target_responsive": target_responsive,
        }

    def propose_hypothesis(
        self,
        session: Session,
        target_info: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Formulate the next testable claim from observations."""
        target_id = target_info.get("id", session.active_target)
        port = target_info.get("port", 8080)
        facts = self.analyze_observations(session)

        # Existing claims to avoid duplicates
        existing_claims = {h.claim for h in session.hypotheses}

        # Case 1: Initial connectivity
        if not facts["root_observed"]:
            init_claim = f"Target HTTP service '{target_id}' is accessible on port {port}"
            if init_claim not in existing_claims:
                # Must be based on at least one observation
                obs_ids = [o.observation_id for o in session.observations]
                if obs_ids:
                    return {
                        "claim": init_claim,
                        "based_on_observations": [obs_ids[0]],
                        "target_path": "/",
                    }

        # Case 2: robots.txt crawling restrictions
        if facts["root_observed"] and not facts["robots_observed"]:
            robots_claim = "Target HTTP service exposes /robots.txt with crawling guidelines and path definitions"
            if (
                robots_claim not in existing_claims
                and "/robots.txt" not in facts["failed_paths"]
                and not session.is_approach_failed("http_probe", {"path": "/robots.txt", "method": "GET"})
            ):
                root_obs = next((o for o in session.observations if o.attributes.get("path") == "/"), None)
                obs_id = root_obs.observation_id if root_obs else session.observations[0].observation_id
                return {
                    "claim": robots_claim,
                    "based_on_observations": [obs_id],
                    "target_path": "/robots.txt",
                }

        # Case 3: Paths discovered via robots.txt
        if facts["disallowed_paths"]:
            robots_obs = next((o for o in session.observations if o.attributes.get("path") == "/robots.txt"), None)
            base_obs_id = robots_obs.observation_id if robots_obs else session.observations[0].observation_id

            for path in sorted(list(facts["disallowed_paths"])):
                if path in facts["known_paths"] or path in facts["failed_paths"]:
                    continue

                if session.is_approach_failed("http_probe", {"path": path, "method": "GET"}):
                    continue

                path_claim = f"Explicitly referenced path '{path}' declared in robots.txt is accessible on target"
                if path_claim not in existing_claims:
                    return {
                        "claim": path_claim,
                        "based_on_observations": [base_obs_id],
                        "target_path": path,
                    }

        # Case 4: Server technology identification
        server_header = facts["observed_headers"].get("Server")
        if server_header:
            server_claim = f"Target web service responds with Server identification '{server_header}'"
            if server_claim not in existing_claims:
                obs_ids = [o.observation_id for o in session.observations]
                return {
                    "claim": server_claim,
                    "based_on_observations": [obs_ids[0]],
                    "target_path": "/",
                }

        return None

    def propose_safe_test(
        self,
        session: Session,
        hypothesis: Hypothesis,
        target_info: Dict[str, Any],
        target_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Propose a bounded SafeTest strictly adhering to safety rules."""
        target_id = target_info.get("id", session.active_target)

        # Extract target path from parameters or claim text
        path = target_path
        if not path:
            # Extract path from claim if present (e.g. path in quotes)
            match = re.search(r"['\"](/\S*)['\"]", hypothesis.claim)
            if match:
                path = match.group(1)
            elif "/robots.txt" in hypothesis.claim:
                path = "/robots.txt"
            else:
                path = "/"

        params = {"path": path, "method": "GET"}

        # Enforce failed-approach avoidance rule
        if session.is_approach_failed("http_probe", params):
            return None

        # Check if identical test is already pending in session
        for existing_test in session.safe_tests:
            if existing_test.hypothesis_id == hypothesis.hypothesis_id and existing_test.parameters == params:
                return None

        return {
            "tool": "http_probe",
            "safety_justification": f"Read-only HTTP GET to safe endpoint '{path}' on allowlisted target '{target_id}'",
            "expected_outcome": f"HTTP status and headers for '{path}' to evaluate hypothesis claim",
            "parameters": params,
        }

    def evaluate_result(
        self,
        session: Session,
        safe_test: SafeTest,
        test_result: TestResult,
        evidence_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Evaluate test result against hypothesis and deduce conclusion supported by evidence."""
        status_code = evidence_payload.get("status_code", 0)
        path = safe_test.parameters.get("path", "/")
        body = evidence_payload.get("body", "")
        headers = evidence_payload.get("headers", {})

        new_observations: List[Dict[str, Any]] = []

        if test_result.status == TestStatus.SUCCESS.value and 200 <= status_code < 400:
            conclusion_status = ConclusionStatus.VALIDATED.value
            rationale = (
                f"Test '{safe_test.test_id}' confirmed hypothesis. Received HTTP {status_code} "
                f"for path '{path}' backed by evidence {test_result.evidence_ref}."
            )

            # Discover new facts to feed back into observation registry
            disallowed_paths = []
            if path == "/robots.txt":
                # Parse Disallow entries
                for line in body.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            dis_path = parts[1].strip()
                            if dis_path.startswith("/"):
                                disallowed_paths.append(dis_path)

            obs_desc = f"HTTP {status_code} response for path '{path}'"
            if disallowed_paths:
                obs_desc += f" disclosing disallowed paths: {disallowed_paths}"

            new_observations.append({
                "description": obs_desc,
                "attributes": {
                    "path": path,
                    "status_code": status_code,
                    "headers": headers,
                    "disallowed_paths": disallowed_paths,
                },
            })

        else:
            conclusion_status = ConclusionStatus.REFUTED.value
            rationale = (
                f"Test '{safe_test.test_id}' refuted hypothesis. Endpoint '{path}' returned "
                f"HTTP {status_code} (or request failed) backed by evidence {test_result.evidence_ref}."
            )

        return {
            "conclusion_status": conclusion_status,
            "rationale": rationale,
            "new_observations": new_observations,
        }
