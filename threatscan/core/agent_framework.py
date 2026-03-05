"""
ThreatScan Agent Framework
===========================
Base classes implementing the OODA (Observe-Orient-Decide-Act) cognitive loop,
shared blackboard architecture, and inter-agent communication protocol.

Every agent in the Hive inherits from BaseAgent and implements its own
OODA cycle. Agents communicate via the Blackboard (shared knowledge graph)
and the EventBus (pub/sub for real-time coordination).
"""

import asyncio
import uuid
import time
import logging
from abc import ABC, abstractmethod
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Any, Optional, Callable, Coroutine
from collections import defaultdict

logger = logging.getLogger("threatscan.core")


# ─────────────────────────────────────────────────────────
# Agent Lifecycle & Status
# ─────────────────────────────────────────────────────────

class AgentStatus(Enum):
    IDLE = auto()
    OBSERVING = auto()
    ORIENTING = auto()
    DECIDING = auto()
    ACTING = auto()
    WAITING = auto()
    ERROR = auto()
    TERMINATED = auto()


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "info"

    @property
    def numeric(self) -> float:
        return {
            "critical": 9.5, "high": 7.5, "medium": 5.0,
            "low": 2.5, "info": 0.5
        }[self.value]


class AgentRole(Enum):
    COMMANDER = "commander"
    SHADOW = "shadow"        # Recon
    HUNTER = "hunter"        # Vulnerability Discovery
    RED_TEAM = "red_team"    # Adversarial Verification
    ARCHITECT = "architect"  # Remediation
    HISTORIAN = "historian"  # Memory & Learning


# ─────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    id: str = field(default_factory=lambda: f"FIND-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.INFORMATIONAL
    category: str = ""          # e.g., "sql_injection", "xss", "hardcoded_secret"
    cwe_id: Optional[str] = None
    cvss_score: float = 0.0
    asset: str = ""             # affected endpoint/file/service
    evidence: str = ""          # proof of vulnerability
    remediation: str = ""
    confidence: float = 0.0     # 0.0 to 1.0
    verified: bool = False
    exploitable: bool = False
    attack_chain: list = field(default_factory=list)
    discovered_by: str = ""
    verified_by: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)


@dataclass
class ScanTarget:
    id: str = field(default_factory=lambda: f"TGT-{uuid.uuid4().hex[:8].upper()}")
    target_type: str = ""       # "url", "repo", "ip", "container", "code_snippet"
    value: str = ""             # the actual URL/repo/IP
    scope: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class TaskNode:
    """A node in the Hierarchical Task Network (HTN)"""
    id: str = field(default_factory=lambda: f"TASK-{uuid.uuid4().hex[:8].upper()}")
    name: str = ""
    description: str = ""
    level: int = 0              # 0=strategic, 1=tactical, 2=operational, 3=atomic
    assigned_to: Optional[AgentRole] = None
    status: str = "pending"     # pending, running, completed, failed, skipped
    priority: float = 0.0       # TOPSIS score
    subtasks: list = field(default_factory=list)
    dependencies: list = field(default_factory=list)
    result: Any = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class AttackSurfaceNode:
    """Node in the Attack Surface Graph"""
    id: str = field(default_factory=lambda: f"ASN-{uuid.uuid4().hex[:8].upper()}")
    node_type: str = ""         # "endpoint", "service", "port", "dependency", "file"
    name: str = ""
    properties: dict = field(default_factory=dict)
    risk_score: float = 0.0
    connections: list = field(default_factory=list)


# ─────────────────────────────────────────────────────────
# Event Bus — Pub/Sub for Agent Communication
# ─────────────────────────────────────────────────────────

class EventBus:
    """
    Decoupled pub/sub system for inter-agent communication.
    Agents subscribe to event types and get notified asynchronously.
    """

    def __init__(self):
        self._subscribers: dict[str, list[Callable]] = defaultdict(list)
        self._event_log: list[dict] = []
        self._lock = asyncio.Lock()

    def subscribe(self, event_type: str, handler: Callable[..., Coroutine]):
        self._subscribers[event_type].append(handler)
        logger.debug(f"Subscribed handler to '{event_type}'")

    async def publish(self, event_type: str, data: Any = None, source: str = "system"):
        event = {
            "id": f"EVT-{uuid.uuid4().hex[:8]}",
            "type": event_type,
            "data": data,
            "source": source,
            "timestamp": time.time()
        }

        async with self._lock:
            self._event_log.append(event)

        handlers = self._subscribers.get(event_type, [])
        if handlers:
            await asyncio.gather(
                *[h(event) for h in handlers],
                return_exceptions=True
            )

        # Also notify wildcard subscribers
        for h in self._subscribers.get("*", []):
            await h(event)

    def get_event_log(self, event_type: str = None, limit: int = 100) -> list:
        if event_type:
            return [e for e in self._event_log if e["type"] == event_type][-limit:]
        return self._event_log[-limit:]


# ─────────────────────────────────────────────────────────
# Blackboard — Shared Knowledge Graph
# ─────────────────────────────────────────────────────────

class Blackboard:
    """
    Shared knowledge store accessible by all agents.
    Implements a lightweight in-memory knowledge graph with
    typed nodes, edges, and query support.

    This is the single source of truth — when Shadow discovers
    "target uses JWT with RS256", every agent can see it.
    """

    def __init__(self):
        self._nodes: dict[str, dict] = {}
        self._edges: list[dict] = []
        self._findings: dict[str, Finding] = {}
        self._facts: dict[str, Any] = {}
        self._attack_surface: dict[str, AttackSurfaceNode] = {}
        self._lock = asyncio.Lock()
        self._version = 0

    async def add_node(self, node_id: str, node_type: str, properties: dict = None):
        async with self._lock:
            self._nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "properties": properties or {},
                "created_at": time.time()
            }
            self._version += 1

    async def add_edge(self, source: str, target: str, relation: str, properties: dict = None):
        async with self._lock:
            self._edges.append({
                "source": source,
                "target": target,
                "relation": relation,
                "properties": properties or {},
                "created_at": time.time()
            })
            self._version += 1

    async def set_fact(self, key: str, value: Any, source_agent: str = ""):
        """Store a discovered fact (e.g., 'tech_stack.backend' = 'FastAPI')"""
        async with self._lock:
            self._facts[key] = {
                "value": value,
                "source": source_agent,
                "timestamp": time.time()
            }
            self._version += 1

    async def get_fact(self, key: str) -> Any:
        fact = self._facts.get(key)
        return fact["value"] if fact else None

    async def get_all_facts(self) -> dict:
        return {k: v["value"] for k, v in self._facts.items()}

    async def add_finding(self, finding: Finding):
        async with self._lock:
            self._findings[finding.id] = finding
            self._version += 1

    async def get_findings(self, severity: FindingSeverity = None, verified_only: bool = False) -> list[Finding]:
        findings = list(self._findings.values())
        if severity:
            findings = [f for f in findings if f.severity == severity]
        if verified_only:
            findings = [f for f in findings if f.verified]
        return sorted(findings, key=lambda f: f.cvss_score, reverse=True)

    async def add_attack_surface_node(self, node: AttackSurfaceNode):
        async with self._lock:
            self._attack_surface[node.id] = node
            self._version += 1

    async def get_attack_surface(self) -> dict[str, AttackSurfaceNode]:
        return dict(self._attack_surface)

    async def query_nodes(self, node_type: str = None) -> list[dict]:
        nodes = list(self._nodes.values())
        if node_type:
            nodes = [n for n in nodes if n["type"] == node_type]
        return nodes

    async def query_edges(self, source: str = None, relation: str = None) -> list[dict]:
        edges = self._edges
        if source:
            edges = [e for e in edges if e["source"] == source]
        if relation:
            edges = [e for e in edges if e["relation"] == relation]
        return edges

    async def get_snapshot(self) -> dict:
        """Full state snapshot for dashboard consumption"""
        return {
            "version": self._version,
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "findings": len(self._findings),
            "facts": len(self._facts),
            "attack_surface_nodes": len(self._attack_surface),
            "findings_by_severity": {
                s.value: len([f for f in self._findings.values() if f.severity == s])
                for s in FindingSeverity
            }
        }


# ─────────────────────────────────────────────────────────
# Base Agent — OODA Cognitive Loop
# ─────────────────────────────────────────────────────────

class BaseAgent(ABC):
    """
    Abstract base class for all ThreatScan agents.

    Implements the OODA (Observe-Orient-Decide-Act) loop:
      - Observe:  Gather data from blackboard, event bus, external tools
      - Orient:   Analyze observations against mental models, prior knowledge
      - Decide:   Select the best course of action using decision algorithms
      - Act:      Execute the chosen action, write results back

    Each agent runs its OODA loop continuously until terminated or
    the scan is complete.
    """

    def __init__(
        self,
        role: AgentRole,
        blackboard: Blackboard,
        event_bus: EventBus,
        config: dict = None
    ):
        self.id = f"{role.value}-{uuid.uuid4().hex[:6]}"
        self.role = role
        self.blackboard = blackboard
        self.event_bus = event_bus
        self.config = config or {}
        self.status = AgentStatus.IDLE
        self.loop_count = 0
        self.observations: list[dict] = []
        self.orientation: dict = {}
        self.decision: Optional[dict] = None
        self._running = False
        self._log: list[dict] = []

        logger.info(f"Agent {self.id} ({self.role.value}) initialized")

    def log(self, message: str, level: str = "info"):
        entry = {
            "agent": self.id,
            "role": self.role.value,
            "message": message,
            "level": level,
            "timestamp": time.time(),
            "loop": self.loop_count,
            "status": self.status.name
        }
        self._log.append(entry)
        getattr(logger, level)(f"[{self.id}] {message}")

    async def emit(self, event_type: str, data: Any = None):
        await self.event_bus.publish(event_type, data=data, source=self.id)

    # ── OODA Methods (override in subclasses) ──

    @abstractmethod
    async def observe(self) -> list[dict]:
        """Gather observations from blackboard, tools, external sources"""
        ...

    @abstractmethod
    async def orient(self, observations: list[dict]) -> dict:
        """Analyze observations — pattern matching, threat modeling, context building"""
        ...

    @abstractmethod
    async def decide(self, orientation: dict) -> dict:
        """Select course of action based on analysis"""
        ...

    @abstractmethod
    async def act(self, decision: dict) -> Any:
        """Execute the decision — scan, verify, remediate, etc."""
        ...

    async def should_continue(self) -> bool:
        """Override to define custom termination conditions"""
        return self._running

    # ── Main Loop ──

    async def run(self, max_loops: int = 50):
        """Execute the OODA loop until termination"""
        self._running = True
        self.log(f"Starting OODA loop (max {max_loops} iterations)")
        await self.emit("agent.started", {"agent": self.id, "role": self.role.value})

        try:
            while self._running and self.loop_count < max_loops:
                self.loop_count += 1
                self.log(f"─── OODA Loop #{self.loop_count} ───")

                # O — OBSERVE
                self.status = AgentStatus.OBSERVING
                self.observations = await self.observe()
                self.log(f"Observed {len(self.observations)} items")

                if not self.observations:
                    self.log("No observations — entering wait state")
                    self.status = AgentStatus.WAITING
                    await asyncio.sleep(0.5)
                    continue

                # O — ORIENT
                self.status = AgentStatus.ORIENTING
                self.orientation = await self.orient(self.observations)
                self.log(f"Orientation complete: {self.orientation.get('summary', 'N/A')}")

                # D — DECIDE
                self.status = AgentStatus.DECIDING
                self.decision = await self.decide(self.orientation)
                self.log(f"Decision: {self.decision.get('action', 'none')}")

                if self.decision.get("action") == "terminate":
                    self.log("Decision to terminate — exiting loop")
                    break

                # A — ACT
                self.status = AgentStatus.ACTING
                result = await self.act(self.decision)
                self.log(f"Action complete: {type(result).__name__}")

                await self.emit("agent.loop_complete", {
                    "agent": self.id,
                    "loop": self.loop_count,
                    "decision": self.decision.get("action"),
                    "result_summary": str(result)[:200] if result else None
                })

                # Check termination
                if not await self.should_continue():
                    break

                await asyncio.sleep(0.1)  # yield control

        except Exception as e:
            self.status = AgentStatus.ERROR
            self.log(f"Fatal error: {e}", level="error")
            await self.emit("agent.error", {"agent": self.id, "error": str(e)})
            raise
        finally:
            self._running = False
            self.status = AgentStatus.TERMINATED
            await self.emit("agent.terminated", {
                "agent": self.id,
                "loops": self.loop_count,
                "role": self.role.value
            })
            self.log(f"Terminated after {self.loop_count} loops")

    async def stop(self):
        self._running = False

    def get_telemetry(self) -> dict:
        return {
            "id": self.id,
            "role": self.role.value,
            "status": self.status.name,
            "loop_count": self.loop_count,
            "log_entries": len(self._log),
            "recent_log": self._log[-5:] if self._log else []
        }
