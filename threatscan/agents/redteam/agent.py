"""
Red Team Agent ("Adversarial Verification")
=============================================
Attempts controlled exploitation to confirm vulnerabilities.
Thinks like an attacker — synthesizes custom exploits, tests
evasion against defense layers.

Key Algorithms:
  - Tree-of-Thought (ToT) multi-strategy exploit planning
  - RAG-powered exploit synthesis from knowledge base
  - Sandboxed execution with eBPF-style tracing
  - Evasion difficulty scoring against WAF/SIEM/EDR
"""

import asyncio
import random
import time
import hashlib
from dataclasses import dataclass, field
from typing import Optional

from ...core.agent_framework import (
    BaseAgent, AgentRole, Blackboard, EventBus,
    Finding, FindingSeverity
)
from ...config import settings
from ...core.llm_client import llm


# ─────────────────────────────────────────────────────────
# Exploit Knowledge Base (RAG Source)
# ─────────────────────────────────────────────────────────

EXPLOIT_KNOWLEDGE_BASE = {
    "sql_injection": {
        "techniques": [
            {
                "name": "Union-Based SQLi",
                "template": "' UNION SELECT {columns} FROM {table}--",
                "success_rate": 0.7,
                "evasion_difficulty": 0.4,
                "prerequisites": ["error-based-response", "known-column-count"]
            },
            {
                "name": "Boolean Blind SQLi",
                "template": "' AND (SELECT CASE WHEN ({condition}) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)--",
                "success_rate": 0.85,
                "evasion_difficulty": 0.6,
                "prerequisites": ["boolean-differentiation"]
            },
            {
                "name": "Time-Based Blind SQLi",
                "template": "'; WAITFOR DELAY '00:00:{delay}'--",
                "success_rate": 0.9,
                "evasion_difficulty": 0.7,
                "prerequisites": []
            },
            {
                "name": "Stacked Query SQLi",
                "template": "'; {malicious_query};--",
                "success_rate": 0.5,
                "evasion_difficulty": 0.3,
                "prerequisites": ["multi-statement-support"]
            },
        ]
    },
    "xss": {
        "techniques": [
            {
                "name": "Reflected XSS via Event Handler",
                "template": '"><img src=x onerror={payload}>',
                "success_rate": 0.6,
                "evasion_difficulty": 0.5,
                "prerequisites": ["reflected-input"]
            },
            {
                "name": "DOM-Based XSS",
                "template": "javascript:/*--></title></style></textarea></script><svg/onload='{payload}'>",
                "success_rate": 0.55,
                "evasion_difficulty": 0.7,
                "prerequisites": ["dom-sink"]
            },
            {
                "name": "Polyglot XSS",
                "template": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert({payload}) )//",
                "success_rate": 0.75,
                "evasion_difficulty": 0.8,
                "prerequisites": []
            },
        ]
    },
    "command_injection": {
        "techniques": [
            {
                "name": "Pipe Injection",
                "template": "| {command}",
                "success_rate": 0.6,
                "evasion_difficulty": 0.3,
                "prerequisites": ["shell-context"]
            },
            {
                "name": "Backtick Injection",
                "template": "`{command}`",
                "success_rate": 0.5,
                "evasion_difficulty": 0.4,
                "prerequisites": ["shell-context"]
            },
            {
                "name": "Newline Injection",
                "template": "%0a{command}",
                "success_rate": 0.7,
                "evasion_difficulty": 0.6,
                "prerequisites": []
            },
        ]
    },
    "auth_bypass": {
        "techniques": [
            {
                "name": "JWT None Algorithm",
                "template": '{"alg":"none","typ":"JWT"}.{payload}.""',
                "success_rate": 0.4,
                "evasion_difficulty": 0.2,
                "prerequisites": ["jwt-auth"]
            },
            {
                "name": "JWT Key Confusion (RS256→HS256)",
                "template": "sign_with_public_key(header={alg:HS256}, payload={admin:true})",
                "success_rate": 0.5,
                "evasion_difficulty": 0.5,
                "prerequisites": ["jwt-auth", "public-key-accessible"]
            },
            {
                "name": "Parameter Pollution",
                "template": "?role=user&role=admin",
                "success_rate": 0.35,
                "evasion_difficulty": 0.3,
                "prerequisites": []
            },
            {
                "name": "Mass Assignment",
                "template": '{"username":"test","password":"test","isAdmin":true}',
                "success_rate": 0.45,
                "evasion_difficulty": 0.2,
                "prerequisites": ["json-body-accepted"]
            },
        ]
    },
    "path_traversal": {
        "techniques": [
            {
                "name": "Classic Traversal",
                "template": "../../../etc/passwd",
                "success_rate": 0.5,
                "evasion_difficulty": 0.3,
                "prerequisites": ["file-path-parameter"]
            },
            {
                "name": "Null Byte Injection",
                "template": "../../../etc/passwd%00.jpg",
                "success_rate": 0.3,
                "evasion_difficulty": 0.5,
                "prerequisites": ["file-extension-check"]
            },
            {
                "name": "Double URL Encoding",
                "template": "..%252f..%252f..%252fetc%252fpasswd",
                "success_rate": 0.6,
                "evasion_difficulty": 0.7,
                "prerequisites": []
            },
        ]
    },
}

# Defense detection signatures
WAF_SIGNATURES = {
    "sql_patterns": ["UNION", "SELECT", "DROP", "INSERT", "DELETE", "--", "/*", "*/", "SLEEP", "WAITFOR"],
    "xss_patterns": ["<script", "onerror", "onload", "javascript:", "alert(", "document."],
    "traversal_patterns": ["../", "..\\", "%2e%2e", "etc/passwd"],
    "command_patterns": ["|", ";", "`", "$(", "%0a"],
}


# ─────────────────────────────────────────────────────────
# Tree-of-Thought Exploit Planner
# ─────────────────────────────────────────────────────────

@dataclass
class ThoughtNode:
    """A node in the Tree-of-Thought exploration"""
    id: str
    strategy: str
    technique: str
    payload: str
    score: float = 0.0          # estimated success probability
    evasion_score: float = 0.0  # estimated WAF evasion probability
    children: list = field(default_factory=list)
    result: Optional[dict] = None
    pruned: bool = False
    depth: int = 0


class TreeOfThoughtPlanner:
    """
    Tree-of-Thought (ToT) multi-strategy exploit planning.

    Generates multiple exploitation strategies in parallel,
    evaluates each branch for likelihood of success, prunes
    unlikely branches, and pursues the most promising paths.

    This mimics how an experienced pentester thinks:
      "I could try SQLi via union... or maybe blind... 
       the union approach needs column count, let me try blind first"

    Algorithm:
      1. Generate K initial thought branches (strategies)
      2. For each branch, expand with specific techniques
      3. Score each leaf (success probability × evasion difficulty)
      4. Prune branches below threshold
      5. Deep-dive the top branches with payload refinement
      6. Select the optimal attack path
    """

    def __init__(self, branching_factor: int = 3, max_depth: int = 4, prune_threshold: float = 0.2):
        self.branching_factor = branching_factor
        self.max_depth = max_depth
        self.prune_threshold = prune_threshold
        self.nodes_explored = 0
        self.nodes_pruned = 0

    def plan(self, vulnerability_type: str, context: dict = None) -> list[ThoughtNode]:
        """
        Generate and evaluate a Tree-of-Thought for exploiting a vulnerability.

        Args:
            vulnerability_type: Category of vulnerability to exploit
            context: Environmental context (tech stack, WAF presence, etc.)

        Returns:
            Ranked list of attack strategies (best first)
        """
        context = context or {}
        kb = EXPLOIT_KNOWLEDGE_BASE.get(vulnerability_type, {})
        techniques = kb.get("techniques", [])

        if not techniques:
            return []

        # Phase 1: Generate initial thought branches
        root_thoughts = []
        for tech in techniques[:self.branching_factor]:
            node = ThoughtNode(
                id=f"T-{hashlib.md5(tech['name'].encode()).hexdigest()[:6]}",
                strategy=tech["name"],
                technique=vulnerability_type,
                payload=tech["template"],
                score=tech["success_rate"],
                evasion_score=tech["evasion_difficulty"],
                depth=0
            )
            root_thoughts.append(node)
            self.nodes_explored += 1

        # Phase 2: Expand each branch with payload variants
        for node in root_thoughts:
            if node.score < self.prune_threshold:
                node.pruned = True
                self.nodes_pruned += 1
                continue

            variants = self._generate_payload_variants(node.payload, vulnerability_type)
            for variant in variants[:self.branching_factor]:
                child = ThoughtNode(
                    id=f"T-{hashlib.md5(variant.encode()).hexdigest()[:6]}",
                    strategy=f"{node.strategy} (variant)",
                    technique=vulnerability_type,
                    payload=variant,
                    score=node.score * random.uniform(0.7, 1.1),
                    evasion_score=node.evasion_score * random.uniform(0.8, 1.2),
                    depth=1
                )
                node.children.append(child)
                self.nodes_explored += 1

        # Phase 3: Score and rank
        all_leaves = []
        for root in root_thoughts:
            if root.pruned:
                continue
            if root.children:
                all_leaves.extend(root.children)
            else:
                all_leaves.append(root)

        # Combined score: success_rate × evasion_capability
        for leaf in all_leaves:
            leaf.score = leaf.score * (0.5 + 0.5 * leaf.evasion_score)

        # Sort by combined score
        all_leaves.sort(key=lambda n: n.score, reverse=True)

        return all_leaves

    def _generate_payload_variants(self, base_payload: str, vuln_type: str) -> list[str]:
        """Generate encoding and evasion variants of a payload"""
        variants = [base_payload]

        # URL encoding variants
        variants.append(base_payload.replace("'", "%27").replace('"', "%22"))
        variants.append(base_payload.replace("<", "%3C").replace(">", "%3E"))

        # Case variation
        variants.append(base_payload.swapcase())

        # Double encoding
        variants.append(base_payload.replace("'", "%2527"))

        # Unicode variants
        variants.append(base_payload.replace("'", "＇").replace('"', '＂'))

        # Comment insertion (SQL)
        if vuln_type == "sql_injection":
            variants.append(base_payload.replace(" ", "/**/"))

        return variants


# ─────────────────────────────────────────────────────────
# Sandbox Execution Environment
# ─────────────────────────────────────────────────────────

@dataclass
class ExecutionTrace:
    """Full execution trace of an exploit attempt"""
    exploit_id: str
    payload: str
    started_at: float
    completed_at: float = 0.0
    success: bool = False
    syscalls: list = field(default_factory=list)
    network_activity: list = field(default_factory=list)
    memory_events: list = field(default_factory=list)
    response: dict = field(default_factory=dict)
    error: Optional[str] = None


class SandboxExecutor:
    """
    Sandboxed exploit execution environment.

    In production: Firecracker microVM or gVisor container with eBPF tracing.
    Here: simulated execution with realistic trace generation.

    Records:
      - System calls made
      - Network activity
      - Memory operations
      - Response data
    """

    def __init__(self):
        self.traces: list[ExecutionTrace] = []

    async def execute(self, payload: str, target_context: dict = None) -> ExecutionTrace:
        """Execute an exploit payload in the sandbox and record the trace"""
        trace = ExecutionTrace(
            exploit_id=f"EXP-{hashlib.md5(payload.encode()).hexdigest()[:8]}",
            payload=payload,
            started_at=time.time()
        )

        # Simulate execution
        await asyncio.sleep(0.01)  # simulate processing time

        # Determine if exploit succeeds based on payload characteristics
        success_indicators = {
            "UNION SELECT": 0.6, "OR '1'='1": 0.5, "alert(": 0.4,
            "onerror": 0.5, "../../../": 0.4, "| ": 0.3,
            "alg\":\"none": 0.35, "isAdmin\":true": 0.4,
            "%00": 0.25, "SLEEP(": 0.7, "WAITFOR": 0.7,
        }

        success_prob = 0.1
        for indicator, prob in success_indicators.items():
            if indicator in payload:
                success_prob = max(success_prob, prob)

        trace.success = random.random() < success_prob

        # Generate realistic trace data
        trace.syscalls = self._generate_syscall_trace(payload, trace.success)
        trace.network_activity = self._generate_network_trace(payload, trace.success)
        trace.response = {
            "status": 200 if trace.success else random.choice([400, 403, 500]),
            "body_preview": self._generate_response_body(payload, trace.success),
            "headers": {"X-Request-Id": hashlib.md5(payload.encode()).hexdigest()[:12]}
        }

        trace.completed_at = time.time()
        self.traces.append(trace)
        return trace

    def _generate_syscall_trace(self, payload: str, success: bool) -> list[dict]:
        """Generate simulated eBPF syscall trace"""
        base_calls = [
            {"syscall": "socket", "args": ["AF_INET", "SOCK_STREAM"], "result": "fd=3"},
            {"syscall": "connect", "args": ["fd=3", "target:443"], "result": "0"},
            {"syscall": "write", "args": ["fd=3", f"payload_len={len(payload)}"], "result": str(len(payload))},
            {"syscall": "read", "args": ["fd=3", "buf_size=4096"], "result": "bytes_read"},
        ]

        if success and "etc/passwd" in payload:
            base_calls.append(
                {"syscall": "open", "args": ["/etc/passwd", "O_RDONLY"], "result": "fd=4", "anomalous": True}
            )
        if success and any(cmd in payload for cmd in ["|", "`", "$("]):
            base_calls.append(
                {"syscall": "execve", "args": ["/bin/sh", "-c"], "result": "0", "anomalous": True}
            )

        return base_calls

    def _generate_network_trace(self, payload: str, success: bool) -> list[dict]:
        """Generate simulated network activity"""
        return [
            {"type": "tcp_connect", "dst": "target:443", "timestamp": time.time()},
            {"type": "tls_handshake", "version": "TLS 1.3", "cipher": "AES-256-GCM"},
            {"type": "http_request", "method": "POST", "path": "/api/endpoint",
             "payload_size": len(payload)},
            {"type": "http_response", "status": 200 if success else 403,
             "size": random.randint(100, 5000)},
        ]

    def _generate_response_body(self, payload: str, success: bool) -> str:
        if not success:
            return '{"error": "Forbidden"}'
        if "etc/passwd" in payload:
            return "root:x:0:0:root:/root:/bin/bash\\nnobody:x:65534:65534..."
        if "UNION SELECT" in payload:
            return '[{"username":"admin","password_hash":"$2b$12$...","role":"admin"}]'
        if "alert(" in payload:
            return '<html><body>...reflected content...</body></html>'
        return '{"status": "success", "data": "..."}'


# ─────────────────────────────────────────────────────────
# Evasion Scorer
# ─────────────────────────────────────────────────────────

class EvasionScorer:
    """
    Tests whether an exploit would be caught by common defenses.
    Scores the evasion difficulty — how hard would it be for an
    attacker to exploit this without getting caught?

    Simulates:
      - WAF (Web Application Firewall) detection
      - SIEM rule matching
      - EDR behavioral detection
    """

    def score(self, payload: str, vuln_type: str) -> dict:
        """
        Score how detectable an exploit payload is.
        Returns: {waf_detected, siem_detected, edr_detected, overall_evasion_score}
        """
        # WAF detection — pattern matching
        waf_detected = False
        waf_patterns_matched = []
        for category, patterns in WAF_SIGNATURES.items():
            for pattern in patterns:
                if pattern.lower() in payload.lower():
                    waf_detected = True
                    waf_patterns_matched.append(pattern)

        # SIEM detection — anomaly-based (simplified)
        siem_score = 0.0
        if len(payload) > 500:
            siem_score += 0.3  # unusually long input
        if payload.count("'") > 3 or payload.count('"') > 3:
            siem_score += 0.2  # excessive quotes
        if any(c in payload for c in [";", "|", "`"]):
            siem_score += 0.3  # shell metacharacters
        siem_detected = siem_score > 0.5

        # EDR detection — behavioral (would detect post-exploitation)
        edr_indicators = ["exec", "system", "spawn", "child_process", "subprocess"]
        edr_detected = any(ind in payload.lower() for ind in edr_indicators)

        # Overall evasion score (1.0 = completely evasive, 0.0 = easily caught)
        detection_count = sum([waf_detected, siem_detected, edr_detected])
        overall = max(0.0, 1.0 - (detection_count * 0.33))

        return {
            "waf_detected": waf_detected,
            "waf_patterns": waf_patterns_matched[:5],
            "siem_detected": siem_detected,
            "siem_score": siem_score,
            "edr_detected": edr_detected,
            "detection_layers": detection_count,
            "overall_evasion_score": round(overall, 2),
            "verdict": "stealthy" if overall > 0.7 else "moderate" if overall > 0.4 else "easily_detected"
        }


# ─────────────────────────────────────────────────────────
# Red Team Agent
# ─────────────────────────────────────────────────────────

class RedTeamAgent(BaseAgent):
    """
    Adversarial verification agent. Attempts controlled exploitation
    to confirm vulnerabilities. Generates PoCs with forensic traces.
    """

    def __init__(self, blackboard: Blackboard, event_bus: EventBus, config: dict = None):
        super().__init__(AgentRole.RED_TEAM, blackboard, event_bus, config)
        self.tot_planner = TreeOfThoughtPlanner(branching_factor=3, max_depth=4)
        self.sandbox = SandboxExecutor()
        self.evasion_scorer = EvasionScorer()
        self.verified_findings: list[dict] = []
        self._findings_to_verify: list[Finding] = []
        self._current_finding_idx = 0

    async def _verify_finding(self, finding: Finding) -> dict:
        """
        Full verification pipeline for a single finding:
          1. LLM-powered ToT exploit reasoning (when API key available)
          2. Heuristic ToT exploit planning (always runs as baseline)
          3. Sandboxed execution of top strategies
          4. Evasion scoring
          5. PoC generation
        """
        self.log(f"Verifying finding: {finding.id} ({finding.category})")

        context = {
            "tech_stack": await self.blackboard.get_fact("detected_framework"),
            "waf_present": await self.blackboard.get_fact("waf_detected") or False,
            "endpoints": len(await self.blackboard.get_fact("discovered_endpoints") or []),
        }

        # Step 1: LLM-powered exploit reasoning (when available)
        llm_strategies = []
        if settings.has_llm:
            self.log(f"  Requesting LLM exploit synthesis for {finding.category}")
            try:
                finding_dict = {
                    "id": finding.id, "title": finding.title,
                    "category": finding.category, "severity": finding.severity.value,
                    "cvss_score": finding.cvss_score, "description": finding.description,
                    "evidence": finding.evidence, "asset": finding.asset,
                }
                llm_result = await llm.synthesize_exploit(finding_dict, context)
                if llm_result and llm_result.get("strategies"):
                    for s in llm_result["strategies"]:
                        node = ThoughtNode(
                            id=f"LLM-{hashlib.md5(s.get('name','').encode()).hexdigest()[:6]}",
                            strategy=f"[LLM] {s.get('name', 'Unknown')}",
                            technique=finding.category,
                            payload=s.get("payload_template", ""),
                            score=float(s.get("success_probability", 0.5)),
                            evasion_score=float(s.get("evasion_difficulty", 0.5)),
                        )
                        llm_strategies.append(node)
                    self.log(f"  LLM synthesized {len(llm_strategies)} strategies "
                             f"(exploitability: {llm_result.get('overall_exploitability', 'unknown')})")
            except Exception as e:
                self.log(f"  LLM exploit synthesis failed: {e}", level="warning")

        # Step 2: Heuristic ToT planning (baseline, always runs)
        strategies = self.tot_planner.plan(finding.category, context)

        # Merge LLM + heuristic strategies, LLM ones first (higher quality)
        all_strategies = llm_strategies + strategies
        if not all_strategies:
            self.log(f"  No exploit strategies for {finding.category}")
            return {"verified": False, "reason": "no_strategies"}

        self.log(f"  Total strategies: {len(all_strategies)} "
                 f"({len(llm_strategies)} LLM + {len(strategies)} heuristic, "
                 f"explored: {self.tot_planner.nodes_explored}, pruned: {self.tot_planner.nodes_pruned})")

        strategies = all_strategies  # use merged list below

        # Step 3: Execute top strategies in sandbox
        successful_exploits = []
        for strategy in strategies[:5]:  # test top 5
            trace = await self.sandbox.execute(strategy.payload, context)

            if trace.success:
                # Step 3: Evasion scoring
                evasion = self.evasion_scorer.score(strategy.payload, finding.category)

                successful_exploits.append({
                    "strategy": strategy.strategy,
                    "payload": strategy.payload[:200],
                    "trace": {
                        "exploit_id": trace.exploit_id,
                        "success": True,
                        "syscalls": len(trace.syscalls),
                        "anomalous_syscalls": sum(1 for s in trace.syscalls if s.get("anomalous")),
                        "response_status": trace.response.get("status"),
                    },
                    "evasion": evasion,
                    "score": strategy.score
                })

        if successful_exploits:
            # Update the finding on the blackboard
            finding.verified = True
            finding.exploitable = True
            finding.verified_by = self.id

            best_exploit = max(successful_exploits, key=lambda e: e["score"])
            finding.evidence = (
                f"Confirmed exploitable via {best_exploit['strategy']}. "
                f"Evasion: {best_exploit['evasion']['verdict']}. "
                f"Sandbox trace: {best_exploit['trace']['exploit_id']}"
            )

            await self.blackboard.add_finding(finding)
            await self.emit("finding.verified", {
                "id": finding.id,
                "exploitable": True,
                "strategy": best_exploit["strategy"],
                "evasion_verdict": best_exploit["evasion"]["verdict"]
            })

            result = {
                "verified": True,
                "exploitable": True,
                "finding_id": finding.id,
                "exploit_count": len(successful_exploits),
                "best_strategy": best_exploit["strategy"],
                "evasion": best_exploit["evasion"],
                "poc": best_exploit
            }
        else:
            finding.verified = True
            finding.exploitable = False
            finding.verified_by = self.id
            await self.blackboard.add_finding(finding)

            result = {
                "verified": True,
                "exploitable": False,
                "finding_id": finding.id,
                "strategies_tested": len(strategies[:5]),
                "reason": "all_strategies_failed"
            }

        self.verified_findings.append(result)
        return result

    # ── OODA Implementation ──

    async def observe(self) -> list[dict]:
        # Get unverified findings from blackboard
        all_findings = await self.blackboard.get_findings()
        unverified = [f for f in all_findings
                      if not f.verified and f.category != "attack_chain"
                      and f.confidence > 0.3]

        if not self._findings_to_verify:
            # Sort by severity (criticals first)
            self._findings_to_verify = sorted(
                unverified, key=lambda f: f.cvss_score, reverse=True
            )

        return [{"type": "findings_queue", "count": len(self._findings_to_verify),
                 "current_idx": self._current_finding_idx}]

    async def orient(self, observations: list[dict]) -> dict:
        queue = observations[0] if observations else {}
        remaining = queue.get("count", 0) - self._current_finding_idx
        return {
            "summary": f"{remaining} findings remaining for verification",
            "has_work": remaining > 0,
            "is_complete": remaining <= 0
        }

    async def decide(self, orientation: dict) -> dict:
        if orientation.get("is_complete"):
            return {"action": "terminate"}
        return {"action": "verify_next"}

    async def act(self, decision: dict) -> dict:
        if decision["action"] == "verify_next" and self._current_finding_idx < len(self._findings_to_verify):
            finding = self._findings_to_verify[self._current_finding_idx]
            result = await self._verify_finding(finding)
            self._current_finding_idx += 1
            return result
        return {}
