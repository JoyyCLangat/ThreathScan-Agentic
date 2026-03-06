"""
ThreatScan LLM Client
======================
Unified interface for all LLM calls across agents.
When ANTHROPIC_API_KEY is set and ENABLE_LLM_ANALYSIS=true,
uses real Claude API. Otherwise returns structured fallback data
so the pipeline continues running without any API keys.

All prompts are security-research focused and produce structured
JSON that agents can parse directly.
"""

import asyncio
import json
import logging
import time
from typing import Any, Optional

from ..config import settings

logger = logging.getLogger("threatscan.llm")

# ── Try to import the Anthropic SDK ───────────────────────────────────────────
try:
    import anthropic as _anthropic_sdk
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False
    logger.debug("anthropic SDK not installed — using HTTP fallback or simulation")

# ── Try httpx/requests for raw HTTP fallback ──────────────────────────────────
try:
    import httpx as _httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


class LLMClient:
    """
    Central LLM client. Agents call this — it handles:
      1. Real Anthropic API (SDK or raw HTTP)
      2. Graceful fallback with heuristic responses when no key is set
      3. Structured JSON output enforcement
      4. Rate limiting and retry logic
    """

    def __init__(self):
        self._client = None
        self._last_call = 0.0
        self._min_interval = 0.5  # 2 req/s max by default
        self._call_count = 0

        if settings.has_llm:
            if _ANTHROPIC_AVAILABLE:
                try:
                    self._client = _anthropic_sdk.Anthropic(api_key=settings.anthropic_api_key)
                    logger.info(f"LLM client initialized (SDK, model={settings.anthropic_model})")
                except Exception as e:
                    logger.warning(f"Failed to init Anthropic SDK: {e}")
            elif _HTTPX_AVAILABLE or _REQUESTS_AVAILABLE:
                logger.info(f"LLM client initialized (HTTP fallback, model={settings.anthropic_model})")
            else:
                logger.warning("No HTTP client available — LLM calls will use simulation")
        else:
            logger.info("LLM client in simulation mode (no API key or ENABLE_LLM_ANALYSIS=false)")

    async def _rate_limit(self):
        """Simple rate limiter."""
        elapsed = time.time() - self._last_call
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)
        self._last_call = time.time()

    async def _call_via_sdk(self, system: str, user: str, model: str, max_tokens: int) -> str:
        """Call Anthropic API via official SDK."""
        await self._rate_limit()
        loop = asyncio.get_event_loop()

        def _sync_call():
            return self._client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}]
            )

        response = await loop.run_in_executor(None, _sync_call)
        return response.content[0].text

    async def _call_via_http(self, system: str, user: str, model: str, max_tokens: int) -> str:
        """Call Anthropic API via raw HTTP when SDK is not installed."""
        await self._rate_limit()
        headers = {
            "x-api-key": settings.anthropic_api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }

        if _HTTPX_AVAILABLE:
            async with _httpx.AsyncClient(timeout=60) as client:
                r = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers, json=payload
                )
                r.raise_for_status()
                return r.json()["content"][0]["text"]
        elif _REQUESTS_AVAILABLE:
            loop = asyncio.get_event_loop()
            def _sync():
                r = _requests.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers, json=payload, timeout=60
                )
                r.raise_for_status()
                return r.json()["content"][0]["text"]
            return await loop.run_in_executor(None, _sync)

        raise RuntimeError("No HTTP client available")

    async def complete(
        self,
        system: str,
        user: str,
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
        fallback: Any = None,
        parse_json: bool = False,
    ) -> Any:
        """
        Make an LLM completion call.

        Args:
            system:     System prompt
            user:       User message
            model:      Override model (default: settings.anthropic_model)
            max_tokens: Override max tokens
            fallback:   Value to return if LLM is unavailable
            parse_json: If True, parse the response as JSON

        Returns:
            String response, or parsed JSON, or fallback value
        """
        model = model or settings.anthropic_model
        max_tokens = max_tokens or settings.anthropic_max_tokens

        if not settings.has_llm:
            return fallback

        self._call_count += 1
        logger.debug(f"LLM call #{self._call_count} to {model}")

        try:
            if self._client and _ANTHROPIC_AVAILABLE:
                text = await self._call_via_sdk(system, user, model, max_tokens)
            else:
                text = await self._call_via_http(system, user, model, max_tokens)

            if parse_json:
                # Strip markdown fences if present
                clean = text.strip()
                if clean.startswith("```"):
                    clean = clean.split("```")[1]
                    if clean.startswith("json"):
                        clean = clean[4:]
                    clean = clean.strip()
                return json.loads(clean)

            return text

        except Exception as e:
            logger.warning(f"LLM call failed: {e} — returning fallback")
            return fallback

    # ── Security-specific prompt methods ─────────────────────────────────────

    async def analyze_code_for_vulns(self, code: str, language: str = "unknown") -> list[dict]:
        """
        Ask the LLM to perform vulnerability analysis on a code snippet.
        Returns a list of structured findings.
        """
        system = """You are an elite application security researcher performing code vulnerability analysis.
Analyze code snippets for security vulnerabilities with the precision of a seasoned penetration tester.
Always respond with valid JSON only — no prose, no markdown, just the JSON object."""

        user = f"""Analyze this {language} code for security vulnerabilities.

```{language}
{code[:4000]}
```

Return a JSON object with this exact structure:
{{
  "findings": [
    {{
      "title": "Short vulnerability title",
      "category": "sql_injection|xss|command_injection|path_traversal|hardcoded_secret|auth_bypass|insecure_deserialization|ssrf|xxe|idor|other",
      "severity": "critical|high|medium|low",
      "cvss_score": 0.0,
      "cwe_id": "CWE-XXX",
      "description": "Detailed technical description",
      "line_numbers": [1, 2],
      "evidence": "Specific code pattern that is vulnerable",
      "remediation": "Concrete fix with code example",
      "confidence": 0.0
    }}
  ],
  "analysis_summary": "Brief overall assessment",
  "attack_vectors": ["vector1", "vector2"]
}}"""

        return await self.complete(
            system=system, user=user,
            model=settings.anthropic_model,
            max_tokens=2048,
            fallback=[],
            parse_json=True
        ) or {"findings": [], "analysis_summary": "LLM unavailable", "attack_vectors": []}

    async def synthesize_exploit(self, finding: dict, context: dict) -> dict:
        """
        Ask the LLM to reason through exploitation strategies for a finding.
        Uses Tree-of-Thought style prompting.
        """
        system = """You are a senior penetration tester writing controlled proof-of-concept exploits 
for a sanctioned security assessment. Your goal is to verify exploitability to help the client 
fix vulnerabilities. Always respond with valid JSON only."""

        user = f"""You are verifying this vulnerability in a controlled security assessment:

Finding: {json.dumps(finding, indent=2)}
Target context: {json.dumps(context, indent=2)}

Using Tree-of-Thought reasoning, generate 3 exploitation strategies ranked by likelihood of success.

Return JSON with this structure:
{{
  "reasoning": "Your step-by-step thinking about this vulnerability",
  "strategies": [
    {{
      "name": "Strategy name",
      "approach": "Detailed technical approach",
      "payload_template": "The actual payload or proof-of-concept",
      "prerequisites": ["prereq1"],
      "success_probability": 0.0,
      "evasion_difficulty": 0.0,
      "detection_risk": "low|medium|high",
      "impact_if_successful": "What an attacker could do"
    }}
  ],
  "recommended_strategy": 0,
  "overall_exploitability": "confirmed|likely|possible|unlikely"
}}"""

        return await self.complete(
            system=system, user=user,
            model=settings.anthropic_model,
            max_tokens=2048,
            fallback=None,
            parse_json=True
        )

    async def generate_patch(self, finding: dict, code_context: str = "") -> dict:
        """
        Ask the LLM to generate a specific, correct patch for a vulnerability.
        """
        system = """You are a senior security engineer generating precise, minimal patches 
for security vulnerabilities. Patches must be correct, idiomatic, and not break existing functionality.
Always respond with valid JSON only."""

        user = f"""Generate a security patch for this vulnerability:

{json.dumps(finding, indent=2)}

{f'Code context:{chr(10)}{code_context[:2000]}' if code_context else ''}

Return JSON with this structure:
{{
  "patch_summary": "One-line description of the fix",
  "language": "python|javascript|java|go|other",
  "vulnerable_pattern": "The pattern that is vulnerable",
  "fix_approach": "The technical approach to fix it",
  "code_before": "The vulnerable code",
  "code_after": "The fixed code",
  "explanation": "Why this fix works",
  "regression_risks": ["potential side effects"],
  "defense_in_depth": [
    "Additional hardening recommendation 1",
    "Additional hardening recommendation 2"
  ],
  "test_case": "A unit test to verify the fix works"
}}"""

        return await self.complete(
            system=system, user=user,
            model=settings.anthropic_model,
            max_tokens=2048,
            fallback=None,
            parse_json=True
        )

    async def generate_executive_report(self, scan_data: dict) -> str:
        """
        Generate a professional executive summary of the scan results.
        """
        system = """You are a CISO-level security consultant writing an executive summary 
of a penetration test. Write clearly for both technical and non-technical audiences.
Be direct, professional, and actionable."""

        user = f"""Write an executive summary for this security scan:

{json.dumps(scan_data, indent=2)[:3000]}

Include:
1. Overall risk assessment and score
2. Most critical findings (top 3) in plain language
3. Business impact if not addressed
4. Prioritized remediation roadmap (immediate/short-term/long-term)
5. Key positive findings (what's working well)

Format as professional prose, about 400 words."""

        return await self.complete(
            system=system, user=user,
            model=settings.anthropic_fast_model,
            max_tokens=1024,
            fallback="[Executive summary unavailable — LLM not configured]"
        )

    async def correlate_attack_chains(self, findings: list[dict]) -> list[dict]:
        """
        Ask the LLM to reason about multi-step attack chains from findings.
        """
        system = """You are a threat modeling expert analyzing how individual vulnerabilities 
chain together into complex attack scenarios. Think like an APT actor.
Always respond with valid JSON only."""

        user = f"""Analyze these security findings and identify realistic multi-step attack chains:

{json.dumps(findings[:20], indent=2)[:3000]}

Return JSON:
{{
  "attack_chains": [
    {{
      "name": "Attack chain name",
      "scenario": "Step-by-step attack narrative",
      "steps": [
        {{"step": 1, "action": "...", "finding_used": "finding_id_or_category"}}
      ],
      "composite_severity": "critical|high|medium",
      "confidence": 0.0,
      "impact": "What the attacker achieves at the end",
      "likelihood": "Probability this would be attempted in the wild"
    }}
  ]
}}"""

        return await self.complete(
            system=system, user=user,
            model=settings.anthropic_model,
            max_tokens=2048,
            fallback={"attack_chains": []},
            parse_json=True
        )


# Singleton
llm = LLMClient()
