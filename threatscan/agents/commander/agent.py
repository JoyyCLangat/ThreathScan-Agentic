"""
Commander Agent ("The Orchestrator")
=====================================
The strategic brain of ThreatScan. Does not scan anything itself —
it plans, delegates, prioritizes, and adapts dynamically.

Key Algorithms:
  - Hierarchical Task Network (HTN) Planning
  - TOPSIS Multi-Criteria Decision Analysis for task prioritization
  - Adaptive re-planning based on downstream discoveries
  - MITRE ATT&CK-informed attack phase modeling
"""

import asyncio
import time
import math
from dataclasses import dataclass, field
from typing import Optional

from ...core.agent_framework import (
    BaseAgent, AgentRole, AgentStatus, Blackboard, EventBus,
    TaskNode, ScanTarget, FindingSeverity
)


# ─────────────────────────────────────────────────────────
# HTN Plan Templates (MITRE ATT&CK-aligned)
# ─────────────────────────────────────────────────────────

TACTICAL_PHASES = [
    {
        "name": "reconnaissance",
        "description": "Map attack surface — enumerate endpoints, services, dependencies, tech stack",
        "assigned_to": AgentRole.SHADOW,
        "priority_base": 1.0,
        "operations": [
            {"name": "passive_osint", "desc": "Certificate transparency, DNS, WHOIS, tech fingerprint"},
            {"name": "active_probing", "desc": "Endpoint discovery, port scan, service fingerprint"},
            {"name": "dependency_audit", "desc": "Build dependency tree, cross-ref NVD/OSV/Snyk"},
            {"name": "js_ast_analysis", "desc": "Parse JS bundles — extract routes, tokens, internal URLs"},
            {"name": "attack_surface_graph", "desc": "Construct directed graph of all discovered assets"},
        ]
    },
    {
        "name": "vulnerability_discovery",
        "description": "Identify vulnerabilities through static + dynamic analysis",
        "assigned_to": AgentRole.HUNTER,
        "priority_base": 0.9,
        "operations": [
            {"name": "taint_analysis", "desc": "Interprocedural dataflow: source → transform → sink"},
            {"name": "abstract_interpretation", "desc": "Type-state analysis for resource lifecycle bugs"},
            {"name": "semantic_pattern_match", "desc": "CodeBERT embedding similarity against vuln templates"},
            {"name": "grammar_fuzzing", "desc": "Coverage-guided grammar-based fuzzing with GA evolution"},
            {"name": "symbolic_execution", "desc": "Z3 constraint solving on critical auth/payment paths"},
            {"name": "behavioral_anomaly", "desc": "VAE baseline → adversarial deviation detection"},
            {"name": "attack_chain_analysis", "desc": "GNN-based multi-step attack path prediction"},
        ]
    },
    {
        "name": "adversarial_verification",
        "description": "Attempt controlled exploitation to confirm vulnerabilities",
        "assigned_to": AgentRole.RED_TEAM,
        "priority_base": 0.85,
        "operations": [
            {"name": "exploit_synthesis", "desc": "RAG-powered custom exploit generation"},
            {"name": "tree_of_thought_attack", "desc": "Multi-strategy parallel exploitation planning"},
            {"name": "sandbox_execution", "desc": "Firecracker microVM exploit validation"},
            {"name": "evasion_scoring", "desc": "Test against WAF/SIEM/EDR detection layers"},
            {"name": "proof_of_concept", "desc": "Generate forensic-grade PoC with execution trace"},
        ]
    },
    {
        "name": "remediation",
        "description": "Generate validated patches and defense-in-depth recommendations",
        "assigned_to": AgentRole.ARCHITECT,
        "priority_base": 0.8,
        "operations": [
            {"name": "patch_synthesis", "desc": "Code-to-code transformer patch generation"},
            {"name": "static_validation", "desc": "Type check + lint the generated patch"},
            {"name": "regression_testing", "desc": "Run existing test suite against patched code"},
            {"name": "rescan_verification", "desc": "Hunter re-scans patched code to confirm fix"},
            {"name": "defense_in_depth", "desc": "Causal BN → systemic recommendations beyond point fix"},
        ]
    },
    {
        "name": "intelligence_synthesis",
        "description": "Record findings, update models, correlate with external threat intel",
        "assigned_to": AgentRole.HISTORIAN,
        "priority_base": 0.7,
        "operations": [
            {"name": "episodic_storage", "desc": "Vector-embed findings into long-term memory"},
            {"name": "rl_update", "desc": "LinUCB reward signal → update detection thresholds"},
            {"name": "threat_correlation", "desc": "Cross-ref with CISA KEV, NVD, dark web feeds"},
            {"name": "report_generation", "desc": "Executive + technical report synthesis"},
        ]
    }
]


# ─────────────────────────────────────────────────────────
# TOPSIS Multi-Criteria Decision Analysis
# ─────────────────────────────────────────────────────────

class TOPSISPrioritizer:
    """
    Technique for Order of Preference by Similarity to Ideal Solution.

    Ranks tasks using weighted criteria:
      - Asset criticality (0-1): Is this a payment endpoint or a static page?
      - Historical vuln density (0-1): Has this component been vulnerable before?
      - Exploit availability (0-1): Are there known exploits in the wild?
      - Blast radius (0-1): If compromised, what's the lateral damage?
      - Time sensitivity (0-1): Is there active exploitation or a recent CVE?

    Weights are derived from Analytic Hierarchy Process (AHP) pairwise comparisons.
    """

    # AHP-derived weights (pre-computed for standard security assessment)
    WEIGHTS = {
        "asset_criticality": 0.30,
        "historical_density": 0.15,
        "exploit_availability": 0.25,
        "blast_radius": 0.20,
        "time_sensitivity": 0.10,
    }

    @staticmethod
    def normalize_matrix(matrix: list[dict]) -> list[dict]:
        """Vector normalization: x_ij / sqrt(sum(x_ij^2))"""
        if not matrix:
            return []

        criteria = list(TOPSISPrioritizer.WEIGHTS.keys())
        norms = {}
        for c in criteria:
            col_sum = sum(row.get(c, 0) ** 2 for row in matrix)
            norms[c] = math.sqrt(col_sum) if col_sum > 0 else 1.0

        normalized = []
        for row in matrix:
            n_row = dict(row)
            for c in criteria:
                n_row[c] = row.get(c, 0) / norms[c]
            normalized.append(n_row)
        return normalized

    @staticmethod
    def weighted_normalize(matrix: list[dict]) -> list[dict]:
        """Apply AHP weights to normalized matrix"""
        weighted = []
        for row in matrix:
            w_row = dict(row)
            for c, w in TOPSISPrioritizer.WEIGHTS.items():
                w_row[c] = row.get(c, 0) * w
            weighted.append(w_row)
        return weighted

    @classmethod
    def rank(cls, tasks: list[dict]) -> list[dict]:
        """
        Full TOPSIS ranking pipeline.
        Returns tasks sorted by closeness coefficient (higher = higher priority).
        """
        if not tasks:
            return []

        criteria = list(cls.WEIGHTS.keys())

        # Step 1-2: Normalize and weight
        normalized = cls.normalize_matrix(tasks)
        weighted = cls.weighted_normalize(normalized)

        # Step 3: Ideal best (A+) and ideal worst (A-)
        # All criteria are benefit criteria (higher = more urgent)
        a_plus = {c: max(row[c] for row in weighted) for c in criteria}
        a_minus = {c: min(row[c] for row in weighted) for c in criteria}

        # Step 4: Euclidean distance to ideal best and worst
        for i, row in enumerate(weighted):
            d_plus = math.sqrt(sum((row[c] - a_plus[c]) ** 2 for c in criteria))
            d_minus = math.sqrt(sum((row[c] - a_minus[c]) ** 2 for c in criteria))

            # Step 5: Closeness coefficient
            cc = d_minus / (d_plus + d_minus) if (d_plus + d_minus) > 0 else 0
            tasks[i]["topsis_score"] = round(cc, 4)

        return sorted(tasks, key=lambda t: t.get("topsis_score", 0), reverse=True)


# ─────────────────────────────────────────────────────────
# Commander Agent
# ─────────────────────────────────────────────────────────

class CommanderAgent(BaseAgent):
    """
    The Orchestrator. Builds and manages the Hierarchical Task Network,
    delegates to specialist agents, and adaptively re-plans as findings
    emerge from downstream agents.
    """

    def __init__(self, blackboard: Blackboard, event_bus: EventBus, config: dict = None):
        super().__init__(AgentRole.COMMANDER, blackboard, event_bus, config)
        self.htn_root: Optional[TaskNode] = None
        self.scan_target: Optional[ScanTarget] = None
        self.phase_index: int = 0
        self.replan_triggers: list[dict] = []
        self.prioritizer = TOPSISPrioritizer()
        self.agent_registry: dict[AgentRole, BaseAgent] = {}
        self._completed_phases: set = set()

        # Subscribe to events that trigger re-planning
        self.event_bus.subscribe("finding.critical", self._handle_critical_finding)
        self.event_bus.subscribe("recon.tech_discovered", self._handle_tech_discovery)
        self.event_bus.subscribe("agent.error", self._handle_agent_error)

    # ── Agent Registration ──

    def register_agent(self, agent: BaseAgent):
        self.agent_registry[agent.role] = agent
        self.log(f"Registered agent: {agent.id} ({agent.role.value})")

    # ── HTN Construction ──

    def build_htn(self, target: ScanTarget) -> TaskNode:
        """
        Build the full Hierarchical Task Network for a scan.
        Level 0: Strategic objective
        Level 1: Tactical phases (MITRE ATT&CK-aligned)
        Level 2: Operational tasks
        Level 3: Atomic actions (generated dynamically by agents)
        """
        self.scan_target = target
        self.log(f"Building HTN for target: {target.value} ({target.target_type})")

        # Level 0 — Strategic root
        root = TaskNode(
            name="full_security_assessment",
            description=f"Complete security posture assessment of {target.value}",
            level=0,
            priority=1.0
        )

        # Level 1 — Tactical phases
        for phase_template in TACTICAL_PHASES:
            phase_node = TaskNode(
                name=phase_template["name"],
                description=phase_template["description"],
                level=1,
                assigned_to=phase_template["assigned_to"],
                priority=phase_template["priority_base"]
            )

            # Level 2 — Operational tasks
            for op in phase_template["operations"]:
                op_node = TaskNode(
                    name=op["name"],
                    description=op["desc"],
                    level=2,
                    assigned_to=phase_template["assigned_to"],
                    priority=phase_template["priority_base"] * 0.9
                )

                # Assign TOPSIS criteria based on target type
                op_node.metadata["topsis_criteria"] = self._compute_task_criteria(
                    op["name"], target
                )

                phase_node.subtasks.append(op_node)

            root.subtasks.append(phase_node)

        # Set inter-phase dependencies
        for i in range(1, len(root.subtasks)):
            root.subtasks[i].dependencies.append(root.subtasks[i - 1].id)

        self.htn_root = root
        self.log(f"HTN built: {self._count_tasks(root)} total tasks across {len(root.subtasks)} phases")
        return root

    def _compute_task_criteria(self, task_name: str, target: ScanTarget) -> dict:
        """
        Compute TOPSIS criteria for a task based on target characteristics.
        In production this would query the Historian for historical data.
        """
        base = {
            "asset_criticality": 0.5,
            "historical_density": 0.3,
            "exploit_availability": 0.4,
            "blast_radius": 0.5,
            "time_sensitivity": 0.3,
        }

        # Adjust based on target type
        if target.target_type == "url":
            base["exploit_availability"] = 0.7  # web vulns are commonly exploited
            base["blast_radius"] = 0.6
        elif target.target_type == "repo":
            base["historical_density"] = 0.6   # code repos have trackable history
        elif target.target_type == "container":
            base["blast_radius"] = 0.8          # container escape = game over

        # Adjust based on task specialization
        critical_tasks = {"symbolic_execution", "exploit_synthesis", "taint_analysis"}
        if task_name in critical_tasks:
            base["asset_criticality"] = min(base["asset_criticality"] + 0.2, 1.0)

        return base

    def _count_tasks(self, node: TaskNode) -> int:
        count = 1
        for sub in node.subtasks:
            count += self._count_tasks(sub)
        return count

    # ── Adaptive Re-planning ──

    async def _handle_critical_finding(self, event: dict):
        """When a critical finding emerges, re-prioritize and potentially spawn new tasks"""
        finding_data = event.get("data", {})
        self.replan_triggers.append({
            "trigger": "critical_finding",
            "data": finding_data,
            "timestamp": time.time()
        })
        self.log(f"Re-plan trigger: critical finding detected — {finding_data.get('category', 'unknown')}")

    async def _handle_tech_discovery(self, event: dict):
        """When recon discovers new technology, inject specialized scan tasks"""
        tech = event.get("data", {})
        self.replan_triggers.append({
            "trigger": "tech_discovery",
            "data": tech,
            "timestamp": time.time()
        })
        self.log(f"Re-plan trigger: technology discovered — {tech.get('name', 'unknown')}")

    async def _handle_agent_error(self, event: dict):
        """Handle downstream agent failures — reassign or skip"""
        error_data = event.get("data", {})
        self.log(f"Agent error reported: {error_data.get('agent', 'unknown')} — {error_data.get('error', '')}")

    async def replan(self):
        """
        Dynamic re-planning based on accumulated triggers.
        Implements the adaptive HTN modification algorithm:
          1. Process each trigger
          2. Inject new tasks or modify priorities
          3. Re-run TOPSIS on affected phase
          4. Clear processed triggers
        """
        if not self.replan_triggers or not self.htn_root:
            return

        self.log(f"Re-planning: {len(self.replan_triggers)} triggers to process")

        for trigger in self.replan_triggers:
            if trigger["trigger"] == "tech_discovery":
                tech_name = trigger["data"].get("name", "")
                tech_type = trigger["data"].get("type", "")

                # Inject technology-specific scan tasks into the Hunter's phase
                hunter_phase = next(
                    (p for p in self.htn_root.subtasks if p.name == "vulnerability_discovery"),
                    None
                )
                if hunter_phase:
                    specialized_task = TaskNode(
                        name=f"scan_{tech_name.lower().replace(' ', '_')}",
                        description=f"Targeted vulnerability scan for {tech_name} ({tech_type})",
                        level=2,
                        assigned_to=AgentRole.HUNTER,
                        priority=0.95,  # high priority — newly discovered tech
                        metadata={
                            "injected": True,
                            "trigger": "tech_discovery",
                            "technology": tech_name,
                            "topsis_criteria": {
                                "asset_criticality": 0.7,
                                "historical_density": 0.5,
                                "exploit_availability": 0.8,
                                "blast_radius": 0.6,
                                "time_sensitivity": 0.7
                            }
                        }
                    )
                    hunter_phase.subtasks.append(specialized_task)
                    self.log(f"Injected targeted scan task for {tech_name}")

            elif trigger["trigger"] == "critical_finding":
                category = trigger["data"].get("category", "")
                # Escalate the Red Team phase priority
                redteam_phase = next(
                    (p for p in self.htn_root.subtasks if p.name == "adversarial_verification"),
                    None
                )
                if redteam_phase:
                    redteam_phase.priority = min(redteam_phase.priority + 0.1, 1.0)
                    self.log(f"Escalated Red Team priority to {redteam_phase.priority}")

        self.replan_triggers.clear()

    # ── OODA Implementation ──

    async def observe(self) -> list[dict]:
        """
        Commander observes:
          - Current HTN execution state
          - Blackboard state (findings, facts, attack surface)
          - Pending re-plan triggers
          - Agent health telemetry
        """
        observations = []

        # HTN state
        if self.htn_root:
            for phase in self.htn_root.subtasks:
                observations.append({
                    "type": "phase_status",
                    "phase": phase.name,
                    "status": phase.status,
                    "assigned_to": phase.assigned_to.value if phase.assigned_to else None,
                    "subtask_count": len(phase.subtasks),
                    "completed_subtasks": sum(1 for s in phase.subtasks if s.status == "completed")
                })

        # Blackboard snapshot
        snapshot = await self.blackboard.get_snapshot()
        observations.append({"type": "blackboard_state", **snapshot})

        # Agent telemetry
        for role, agent in self.agent_registry.items():
            observations.append({
                "type": "agent_telemetry",
                "role": role.value,
                **agent.get_telemetry()
            })

        # Replan triggers
        if self.replan_triggers:
            observations.append({
                "type": "replan_pending",
                "count": len(self.replan_triggers)
            })

        return observations

    async def orient(self, observations: list[dict]) -> dict:
        """
        Analyze observations to determine operational picture:
          - Which phases are complete?
          - Are there critical findings requiring immediate attention?
          - Do we need to re-plan?
          - Which agents are healthy?
        """
        phase_statuses = [o for o in observations if o["type"] == "phase_status"]
        bb_state = next((o for o in observations if o["type"] == "blackboard_state"), {})
        replan = next((o for o in observations if o["type"] == "replan_pending"), None)

        completed_phases = [p["phase"] for p in phase_statuses if p["status"] == "completed"]
        running_phases = [p["phase"] for p in phase_statuses if p["status"] == "running"]
        pending_phases = [p["phase"] for p in phase_statuses if p["status"] == "pending"]

        # Determine next actionable phase
        next_phase = None
        if pending_phases and not running_phases:
            # Check dependencies
            for phase in self.htn_root.subtasks if self.htn_root else []:
                if phase.status == "pending":
                    deps_met = all(
                        any(p.id == dep_id and p.status == "completed"
                            for p in self.htn_root.subtasks)
                        for dep_id in phase.dependencies
                    ) if phase.dependencies else True
                    if deps_met:
                        next_phase = phase.name
                        break

        return {
            "summary": f"Completed: {len(completed_phases)}, Running: {len(running_phases)}, Pending: {len(pending_phases)}",
            "completed_phases": completed_phases,
            "running_phases": running_phases,
            "pending_phases": pending_phases,
            "next_phase": next_phase,
            "total_findings": bb_state.get("findings", 0),
            "needs_replan": replan is not None,
            "all_complete": len(pending_phases) == 0 and len(running_phases) == 0
        }

    async def decide(self, orientation: dict) -> dict:
        """
        Decision logic:
          1. If re-plan needed → execute re-plan
          2. If a phase is ready to launch → delegate to assigned agent
          3. If all phases complete → terminate
          4. Otherwise → wait
        """
        if orientation.get("all_complete"):
            return {"action": "terminate", "reason": "All phases complete"}

        if orientation.get("needs_replan"):
            return {"action": "replan", "reason": "Triggers pending"}

        if orientation.get("next_phase"):
            # Use TOPSIS to prioritize subtasks within the phase
            phase_name = orientation["next_phase"]
            phase_node = next(
                (p for p in self.htn_root.subtasks if p.name == phase_name),
                None
            )
            if phase_node:
                # Build TOPSIS matrix from subtask criteria
                task_matrix = []
                for subtask in phase_node.subtasks:
                    criteria = subtask.metadata.get("topsis_criteria", {
                        "asset_criticality": 0.5,
                        "historical_density": 0.3,
                        "exploit_availability": 0.4,
                        "blast_radius": 0.5,
                        "time_sensitivity": 0.3,
                    })
                    criteria["task_name"] = subtask.name
                    criteria["task_id"] = subtask.id
                    task_matrix.append(criteria)

                ranked = self.prioritizer.rank(task_matrix)

                return {
                    "action": "launch_phase",
                    "phase": phase_name,
                    "assigned_to": phase_node.assigned_to.value if phase_node.assigned_to else None,
                    "prioritized_tasks": ranked
                }

        return {"action": "wait", "reason": "Awaiting phase completion"}

    async def act(self, decision: dict) -> dict:
        action = decision["action"]

        if action == "replan":
            await self.replan()
            return {"result": "replanned", "triggers_processed": True}

        elif action == "launch_phase":
            phase_name = decision["phase"]
            assigned_role = AgentRole(decision["assigned_to"]) if decision.get("assigned_to") else None

            # Mark phase as running
            for phase in self.htn_root.subtasks:
                if phase.name == phase_name:
                    phase.status = "running"
                    phase.started_at = time.time()
                    break

            # Emit delegation event
            await self.emit("commander.phase_delegated", {
                "phase": phase_name,
                "assigned_to": decision.get("assigned_to"),
                "prioritized_tasks": [
                    {"name": t["task_name"], "score": t.get("topsis_score", 0)}
                    for t in decision.get("prioritized_tasks", [])
                ]
            })

            # Launch the assigned agent
            if assigned_role and assigned_role in self.agent_registry:
                agent = self.agent_registry[assigned_role]
                asyncio.create_task(agent.run(max_loops=30))
                self.log(f"Launched {assigned_role.value} for phase '{phase_name}'")

            return {"result": "phase_launched", "phase": phase_name}

        elif action == "wait":
            await asyncio.sleep(1.0)
            return {"result": "waiting"}

        return {"result": "no_action"}

    # ── Convenience ──

    def get_htn_summary(self) -> dict:
        """Serialize the HTN for dashboard display"""
        if not self.htn_root:
            return {}

        def serialize_task(task: TaskNode) -> dict:
            return {
                "id": task.id,
                "name": task.name,
                "description": task.description,
                "level": task.level,
                "status": task.status,
                "priority": task.priority,
                "assigned_to": task.assigned_to.value if task.assigned_to else None,
                "subtasks": [serialize_task(s) for s in task.subtasks],
                "metadata": task.metadata
            }

        return serialize_task(self.htn_root)
