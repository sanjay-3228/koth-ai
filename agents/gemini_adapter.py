"""Gemini reasoning adapter for KOTH AI.

IMPORTANT ARCHITECTURAL RULE:
Gemini is treated as an UNTRUSTED REASONING COMPONENT.
Gemini must NEVER receive direct shell access.
Gemini must NEVER receive Docker access.
Gemini must NEVER directly execute tools.
Gemini must NEVER bypass the ResearchController.
Gemini must NEVER bypass the Orchestrator.
Gemini must NEVER bypass the Gateway.

Workflow:
Research State
     ↓
Context Builder
     ↓
Gemini
     ↓
UNTRUSTED RESPONSE
     ↓
Strict Schema Validation
     ↓
Validated Research Proposal
     ↓
Research Controller
     ↓
SafeTest
     ↓
Orchestrator
     ↓
Gateway
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
import os
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Set, Union
import urllib.error
import urllib.request

from core.schemas import (
    ConclusionStatus,
    Hypothesis,
    HypothesisStatus,
    Observation,
    SafeTest,
    TestResult,
    TestStatus,
    ValidationError,
    _current_iso_utc,
)
from core.session import ApproachAlreadyFailedError, Session


class GeminiAdapterError(Exception):
    """Base exception for Gemini reasoning adapter errors."""
    pass


class GeminiAPIError(GeminiAdapterError):
    """Raised when communication with the Gemini API fails."""
    pass


class GeminiResponseParsingError(GeminiAdapterError):
    """Raised when the untrusted LLM response cannot be parsed as valid JSON."""
    pass


class GeminiProposalValidationError(GeminiAdapterError):
    """Raised when an untrusted LLM proposal violates security policy or schema constraints."""
    pass


class GeminiProposalType(str, Enum):
    NEW_HYPOTHESIS_AND_TEST = "new_hypothesis_and_test"
    TEST_EXISTING_HYPOTHESIS = "test_existing_hypothesis"
    CONCLUDE = "conclude"


@dataclass
class GeminiProposal:
    """Strongly-typed, validated research proposal produced from Gemini's reasoning."""
    proposal_type: str
    hypothesis_claim: Optional[str] = None
    based_on_observations: List[str] = field(default_factory=list)
    hypothesis_id: Optional[str] = None
    tool: Optional[str] = None
    safety_justification: Optional[str] = None
    expected_outcome: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    target_path: Optional[str] = None
    reasoning: str = ""

    def is_conclusion(self) -> bool:
        return self.proposal_type == GeminiProposalType.CONCLUDE.value

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GeminiContextBuilder:
    """Builds bounded, structured research context for Gemini from the research session state."""

    FORBIDDEN_PATTERNS = [
        "docker.sock",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "aws_secret_access_key",
        "/etc/shadow",
    ]

    def build_context(
        self,
        session: Session,
        target_info: Dict[str, Any],
        allowed_tools: Optional[Set[str]] = None,
        max_tests_remaining: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Compile complete scientific context ensuring no sensitive system details leak."""
        allowed_tools = allowed_tools or {"http_probe"}

        # 1. Target context (authoritative, sanitized)
        target_context = {
            "id": target_info.get("id"),
            "protocol": target_info.get("protocol", "http"),
            "port": target_info.get("port", 8080),
            "network": target_info.get("network", "koth-lab"),
            "container": target_info.get("container", f"koth-{target_info.get('id')}"),
        }

        # 2. Current observations
        observations_context = [
            {
                "observation_id": obs.observation_id,
                "description": obs.description,
                "evidence_ref": obs.evidence_ref,
                "attributes": obs.attributes,
                "timestamp": obs.timestamp,
            }
            for obs in session.observations
        ]

        # 3. Current hypotheses & lifecycles
        hypotheses_context = [
            {
                "hypothesis_id": hyp.hypothesis_id,
                "claim": hyp.claim,
                "status": hyp.status,
                "based_on_observations": hyp.based_on_observations,
                "created_at": hyp.created_at,
                "updated_at": hyp.updated_at,
            }
            for hyp in session.hypotheses
        ]

        # 4. Previous SafeTests and TestResults with immutable evidence references
        test_history = []
        for test in session.safe_tests:
            result = next((r for r in session.test_results if r.test_id == test.test_id), None)
            test_history.append({
                "test_id": test.test_id,
                "hypothesis_id": test.hypothesis_id,
                "tool": test.tool,
                "parameters": test.parameters,
                "safety_justification": test.safety_justification,
                "expected_outcome": test.expected_outcome,
                "result": {
                    "result_id": result.result_id,
                    "status": result.status,
                    "summary": result.summary,
                    "evidence_ref": result.evidence_ref,
                } if result else None,
            })

        # 5. Failed approaches / Negative Knowledge
        failed_approaches_context = [
            {
                "approach_id": fa.approach_id,
                "tool": fa.tool,
                "parameters": fa.parameters,
                "reason": fa.reason,
                "negative_knowledge": fa.negative_knowledge,
                "evidence_ref": fa.evidence_ref,
            }
            for fa in session.failed_approaches
        ]

        # 6. Conclusions & Findings
        conclusions_context = [
            {
                "conclusion_id": c.conclusion_id,
                "hypothesis_id": c.hypothesis_id,
                "status": c.status,
                "rationale": c.rationale,
            }
            for c in session.conclusions
        ]

        findings_context = [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
            }
            for f in session.findings
        ]

        # Bounded execution constraints
        execution_bounds = {
            "allowed_tools": list(allowed_tools),
            "allowed_http_methods": ["GET", "HEAD"],
            "max_tests_remaining": max_tests_remaining,
            "security_rules": [
                "Only interact with the designated target container over the isolated lab network",
                "Never attempt arbitrary shell or bash commands",
                "Never attempt path traversal (..) or shell metacharacters",
                "Never specify custom IP addresses or external hostnames",
                "Do NOT repeat any failed approaches listed in negative knowledge",
            ],
        }

        context = {
            "session_id": session.session_id,
            "target": target_context,
            "observations": observations_context,
            "hypotheses": hypotheses_context,
            "test_history": test_history,
            "failed_approaches": failed_approaches_context,
            "conclusions": conclusions_context,
            "findings": findings_context,
            "bounds": execution_bounds,
        }

        # Sanity check: Ensure no secret patterns are in the prompt
        context_str = json.dumps(context)
        for pat in self.FORBIDDEN_PATTERNS:
            if pat in context_str:
                raise GeminiAdapterError(f"Security invariant violated: sensitive pattern '{pat}' detected in prompt context")

        return context

    def build_prompt(
        self,
        session: Session,
        target_info: Dict[str, Any],
        allowed_tools: Optional[Set[str]] = None,
        max_tests_remaining: Optional[int] = None,
    ) -> str:
        """Render markdown prompt with strict schema guidance for Gemini."""
        context = self.build_context(
            session=session,
            target_info=target_info,
            allowed_tools=allowed_tools,
            max_tests_remaining=max_tests_remaining,
        )

        prompt = (
            "You are an authorized scientific security researcher operating in an isolated KOTH research lab.\n"
            "Your role is STRICT REASONING ONLY. You cannot execute commands or access Docker directly.\n\n"
            "SCIENTIFIC WORKFLOW:\n"
            "1. Observations -> Evidence of existing service properties.\n"
            "2. Hypothesis -> Testable claim strictly based on at least one existing observation.\n"
            "3. Safe Test -> Non-destructive, bounded test strictly using allowed tools.\n"
            "4. Negative Knowledge -> NEVER repeat an approach listed under failed approaches.\n\n"
            "CURRENT RESEARCH STATE:\n"
            f"```json\n{json.dumps(context, indent=2)}\n```\n\n"
            "OUTPUT REQUIREMENTS:\n"
            "Respond ONLY with a valid JSON object matching EXACTLY one of the following proposal formats:\n\n"
            "Option 1: Propose a new hypothesis and a safe test to evaluate it:\n"
            "{\n"
            '  "proposal_type": "new_hypothesis_and_test",\n'
            '  "hypothesis_claim": "Specific testable claim about the target",\n'
            '  "based_on_observations": ["obs-..."],\n'
            '  "tool": "http_probe",\n'
            '  "safety_justification": "Why this test is bounded, non-destructive, and safe",\n'
            '  "expected_outcome": "Expected status or content if hypothesis holds",\n'
            '  "parameters": {"path": "/endpoint", "method": "GET"},\n'
            '  "reasoning": "Scientific reasoning for this step"\n'
            "}\n\n"
            "Option 2: Propose a test for an existing PROPOSED hypothesis:\n"
            "{\n"
            '  "proposal_type": "test_existing_hypothesis",\n'
            '  "hypothesis_id": "hyp-...",\n'
            '  "tool": "http_probe",\n'
            '  "safety_justification": "Why this test is safe and non-destructive",\n'
            '  "expected_outcome": "Expected outcome",\n'
            '  "parameters": {"path": "/endpoint", "method": "GET"},\n'
            '  "reasoning": "Scientific rationale"\n'
            "}\n\n"
            "Option 3: Conclude research (if target objective achieved or no further hypotheses possible):\n"
            "{\n"
            '  "proposal_type": "conclude",\n'
            '  "reasoning": "Summary of conclusions reached"\n'
            "}\n"
        )
        return prompt


class GeminiProposalValidator:
    """Strict schema and security validator for untrusted LLM proposals."""

    FORBIDDEN_PARAMETER_KEYS = {
        "ip",
        "target_ip",
        "host",
        "hostname",
        "port",
        "network",
        "net",
        "subnet",
        "cmd",
        "command",
        "shell",
        "exec",
        "eval",
        "system",
        "script",
        "bash",
        "sh",
    }

    DANGEROUS_CHAR_PATTERN = re.compile(r"[;&|`$<>()\n\r\x00]")

    def validate_proposal(
        self,
        raw_data: Any,
        session: Session,
        target_info: Dict[str, Any],
        allowed_tools: Optional[Set[str]] = None,
    ) -> GeminiProposal:
        """Strictly validate and sanitize an untrusted proposal dict."""
        allowed_tools = allowed_tools or {"http_probe"}

        if not isinstance(raw_data, dict):
            raise GeminiProposalValidationError("Gemini proposal must be a JSON dictionary")

        proposal_type = raw_data.get("proposal_type")
        valid_types = {t.value for t in GeminiProposalType}
        if proposal_type not in valid_types:
            raise GeminiProposalValidationError(
                f"Invalid proposal_type '{proposal_type}'. Expected one of {valid_types}"
            )

        reasoning = str(raw_data.get("reasoning", "")).strip()

        # Handle conclusion
        if proposal_type == GeminiProposalType.CONCLUDE.value:
            return GeminiProposal(
                proposal_type=GeminiProposalType.CONCLUDE.value,
                reasoning=reasoning,
            )

        # Common test proposal validation
        tool = raw_data.get("tool")
        if not tool or not isinstance(tool, str):
            raise GeminiProposalValidationError("Proposal must specify a string 'tool'")

        if tool not in allowed_tools:
            raise GeminiProposalValidationError(
                f"Tool '{tool}' is not in allowed tools: {allowed_tools}"
            )

        safety_justification = raw_data.get("safety_justification")
        if not safety_justification or not isinstance(safety_justification, str) or len(safety_justification.strip()) < 3:
            raise GeminiProposalValidationError("Proposal must include a non-empty 'safety_justification'")

        expected_outcome = raw_data.get("expected_outcome")
        if not expected_outcome or not isinstance(expected_outcome, str) or len(expected_outcome.strip()) < 3:
            raise GeminiProposalValidationError("Proposal must include a non-empty 'expected_outcome'")

        parameters = raw_data.get("parameters")
        if not isinstance(parameters, dict):
            raise GeminiProposalValidationError("Field 'parameters' must be a dictionary")

        # Validate parameters against injection and security policies
        self._validate_parameters(tool, parameters)

        # Check for negative knowledge: approach must not already be failed
        target_id = target_info.get("id", session.active_target)
        if session.is_approach_failed(tool, parameters, target=target_id):
            raise GeminiProposalValidationError(
                f"Proposal violates negative knowledge: tool '{tool}' with parameters {parameters} "
                f"has already failed on target '{target_id}'"
            )

        # Handle specific proposal types
        if proposal_type == GeminiProposalType.NEW_HYPOTHESIS_AND_TEST.value:
            claim = raw_data.get("hypothesis_claim")
            if not claim or not isinstance(claim, str) or len(claim.strip()) < 5:
                raise GeminiProposalValidationError("Field 'hypothesis_claim' must be a descriptive string")

            if len(claim) > 500:
                raise GeminiProposalValidationError("Field 'hypothesis_claim' exceeds maximum length (500 chars)")

            based_on_obs = raw_data.get("based_on_observations")
            if not isinstance(based_on_obs, list) or not based_on_obs:
                raise GeminiProposalValidationError("Field 'based_on_observations' must be a non-empty list")

            valid_obs_ids = {o.observation_id for o in session.observations}
            for obs_id in based_on_obs:
                if not isinstance(obs_id, str):
                    raise GeminiProposalValidationError(f"Observation reference must be a string: {obs_id}")
                if obs_id not in valid_obs_ids:
                    raise GeminiProposalValidationError(
                        f"Observation ID '{obs_id}' does not exist in session observations: {valid_obs_ids}"
                    )

            target_path = parameters.get("path")
            return GeminiProposal(
                proposal_type=proposal_type,
                hypothesis_claim=claim.strip(),
                based_on_observations=list(based_on_obs),
                tool=tool,
                safety_justification=safety_justification.strip(),
                expected_outcome=expected_outcome.strip(),
                parameters=parameters,
                target_path=target_path,
                reasoning=reasoning,
            )

        elif proposal_type == GeminiProposalType.TEST_EXISTING_HYPOTHESIS.value:
            hyp_id = raw_data.get("hypothesis_id")
            if not hyp_id or not isinstance(hyp_id, str):
                raise GeminiProposalValidationError("Field 'hypothesis_id' must be specified for existing hypothesis test")

            valid_hyps = {h.hypothesis_id: h for h in session.hypotheses}
            if hyp_id not in valid_hyps:
                raise GeminiProposalValidationError(
                    f"Hypothesis ID '{hyp_id}' does not exist in session hypotheses: {list(valid_hyps.keys())}"
                )

            hyp = valid_hyps[hyp_id]
            if hyp.status not in (HypothesisStatus.PROPOSED.value, HypothesisStatus.TESTING.value):
                raise GeminiProposalValidationError(
                    f"Cannot propose test for hypothesis '{hyp_id}' in state '{hyp.status}'"
                )

            target_path = parameters.get("path")
            return GeminiProposal(
                proposal_type=proposal_type,
                hypothesis_id=hyp_id,
                tool=tool,
                safety_justification=safety_justification.strip(),
                expected_outcome=expected_outcome.strip(),
                parameters=parameters,
                target_path=target_path,
                reasoning=reasoning,
            )

        raise GeminiProposalValidationError(f"Unhandled proposal type: {proposal_type}")

    def _validate_parameters(self, tool: str, params: Dict[str, Any]) -> None:
        """Enforce strict constraints on tool parameters."""
        # 1. Reject forbidden keys
        for forbidden in self.FORBIDDEN_PARAMETER_KEYS:
            if forbidden in params:
                raise GeminiProposalValidationError(
                    f"Forbidden parameter '{forbidden}' detected in tool request. AI cannot supply host/command attributes."
                )

        if tool == "http_probe":
            # 2. Path validation
            path = params.get("path", "/")
            if not isinstance(path, str):
                raise GeminiProposalValidationError("Parameter 'path' must be a string")

            if not path.startswith("/"):
                raise GeminiProposalValidationError(f"Path must start with '/': {path}")

            if ".." in path:
                raise GeminiProposalValidationError(f"Path traversal detected in path: {path}")

            if self.DANGEROUS_CHAR_PATTERN.search(path):
                raise GeminiProposalValidationError(f"Dangerous characters/metacharacters detected in path: {path}")

            # 3. Method validation
            method = params.get("method", "GET")
            if not isinstance(method, str) or method.upper() not in {"GET", "HEAD"}:
                raise GeminiProposalValidationError(f"HTTP method must be GET or HEAD: {method}")

            # 4. Headers validation
            headers = params.get("headers")
            if headers is not None:
                if not isinstance(headers, dict):
                    raise GeminiProposalValidationError("Parameter 'headers' must be a dictionary")
                for k, v in headers.items():
                    if not isinstance(k, str) or not isinstance(v, str):
                        raise GeminiProposalValidationError("Header keys and values must be strings")
                    if any(c in k for c in ("\r", "\n")) or any(c in v for c in ("\r", "\n")):
                        raise GeminiProposalValidationError("Header keys and values must not contain CRLF characters")


class GeminiClient:
    """Bounded, secure HTTP client for Gemini generateContent endpoint."""

    DEFAULT_MODEL = "gemini-2.0-flash"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[Callable[[str], str]] = None,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model = model or self.DEFAULT_MODEL
        self.provider = provider
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        """Query Gemini or invoke provider callable."""
        # If mock/provider is supplied, use it directly (ideal for unit tests & offline mode)
        if self.provider:
            return self.provider(prompt)

        if not self.api_key:
            raise GeminiAPIError("No Gemini API key provided. Set GEMINI_API_KEY environment variable or pass provider callable.")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
            },
        }

        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_bytes = resp.read()
                data = json.loads(resp_bytes.decode("utf-8"))
                candidates = data.get("candidates", [])
                if not candidates:
                    raise GeminiAPIError("Gemini API returned empty candidate response")
                text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                return text
        except urllib.error.URLError as exc:
            raise GeminiAPIError(f"HTTP request to Gemini failed: {exc}") from exc
        except Exception as exc:
            raise GeminiAPIError(f"Error communicating with Gemini: {exc}") from exc


class GeminiReasoningAdapter:
    """Adapter bridging research state to Gemini and converting output into validated proposals."""

    def __init__(
        self,
        client: Optional[GeminiClient] = None,
        context_builder: Optional[GeminiContextBuilder] = None,
        validator: Optional[GeminiProposalValidator] = None,
        fallback_planner: Optional[Any] = None,
    ):
        self.client = client or GeminiClient()
        self.context_builder = context_builder or GeminiContextBuilder()
        self.validator = validator or GeminiProposalValidator()
        self.fallback_planner = fallback_planner

    def _strip_markdown_fences(self, text: str) -> str:
        """Strip markdown ```json fences if returned by LLM."""
        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()
        return text

    def generate_proposal(
        self,
        session: Session,
        target_info: Dict[str, Any],
        allowed_tools: Optional[Set[str]] = None,
        max_tests_remaining: Optional[int] = None,
    ) -> GeminiProposal:
        """Generate, parse, and validate a research proposal from Gemini."""
        prompt = self.context_builder.build_prompt(
            session=session,
            target_info=target_info,
            allowed_tools=allowed_tools,
            max_tests_remaining=max_tests_remaining,
        )

        raw_text = self.client.generate(prompt)

        # Parse JSON
        cleaned_text = self._strip_markdown_fences(raw_text)
        try:
            raw_json = json.loads(cleaned_text)
        except json.JSONDecodeError as exc:
            raise GeminiResponseParsingError(
                f"Failed to parse Gemini response as JSON: {exc}. Raw text: {raw_text[:200]}"
            ) from exc

        # Strictly validate schema and security constraints
        proposal = self.validator.validate_proposal(
            raw_data=raw_json,
            session=session,
            target_info=target_info,
            allowed_tools=allowed_tools,
        )
        return proposal

    # --- Planner Interface Implementation for ResearchController compatibility ---

    def propose_hypothesis(
        self,
        session: Session,
        target_info: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Formulate next hypothesis claim using Gemini reasoning."""
        try:
            proposal = self.generate_proposal(session, target_info)
            if proposal.is_conclusion():
                return None
            if proposal.proposal_type == GeminiProposalType.NEW_HYPOTHESIS_AND_TEST.value:
                return {
                    "claim": proposal.hypothesis_claim,
                    "based_on_observations": proposal.based_on_observations,
                    "target_path": proposal.target_path,
                }
            return None
        except (GeminiAdapterError, Exception) as exc:
            if self.fallback_planner:
                return self.fallback_planner.propose_hypothesis(session, target_info)
            raise

    def propose_safe_test(
        self,
        session: Session,
        hypothesis: Hypothesis,
        target_info: Dict[str, Any],
        target_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Formulate bounded SafeTest parameters using Gemini reasoning."""
        try:
            proposal = self.generate_proposal(session, target_info)
            if proposal.is_conclusion():
                return None
            if proposal.tool:
                return {
                    "tool": proposal.tool,
                    "safety_justification": proposal.safety_justification,
                    "expected_outcome": proposal.expected_outcome,
                    "parameters": proposal.parameters,
                }
            return None
        except (GeminiAdapterError, Exception) as exc:
            if self.fallback_planner:
                return self.fallback_planner.propose_safe_test(
                    session=session,
                    hypothesis=hypothesis,
                    target_info=target_info,
                    target_path=target_path,
                )
            raise

    def evaluate_result(
        self,
        session: Session,
        safe_test: SafeTest,
        test_result: TestResult,
        evidence_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Evaluate outcome against hypothesis and deduce conclusion."""
        if self.fallback_planner:
            return self.fallback_planner.evaluate_result(
                session=session,
                safe_test=safe_test,
                test_result=test_result,
                evidence_payload=evidence_payload,
            )

        # Baseline scientific evaluation
        status_code = evidence_payload.get("status_code", 0)
        is_success = test_result.status == TestStatus.SUCCESS.value and 200 <= status_code < 400
        concl_status = ConclusionStatus.VALIDATED.value if is_success else ConclusionStatus.REFUTED.value
        rationale = (
            f"Test '{safe_test.test_id}' {'validated' if is_success else 'refuted'} hypothesis. "
            f"Response HTTP {status_code} backed by evidence {test_result.evidence_ref}."
        )

        new_obs: List[Dict[str, Any]] = []
        if is_success:
            path = safe_test.parameters.get("path", "/")
            new_obs.append({
                "description": f"HTTP {status_code} response for path '{path}'",
                "attributes": {
                    "path": path,
                    "status_code": status_code,
                    "headers": evidence_payload.get("headers", {}),
                },
            })

        return {
            "conclusion_status": concl_status,
            "rationale": rationale,
            "new_observations": new_obs,
        }

    evaluate_test_result = evaluate_result

