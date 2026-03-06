"""
ThreatScan Hive — Main Orchestrator
=====================================
Wires all agents together and executes the complete scan pipeline.
This is the entry point for running a full security assessment.
"""

import asyncio
import time
import json
import sys

# Fix imports for standalone execution
sys.path.insert(0, "/home/claude")

from threatscan.config import settings
from threatscan.core.agent_framework import (
    Blackboard, EventBus, ScanTarget, AgentRole
)
from threatscan.agents.commander.agent import CommanderAgent
from threatscan.agents.shadow.agent import ShadowAgent
from threatscan.agents.hunter.agent import HunterAgent
from threatscan.agents.redteam.agent import RedTeamAgent
from threatscan.agents.support.agents import ArchitectAgent, HistorianAgent


class ThreatScanHive:
    """
    The Hive. Coordinates all agents through the complete
    security assessment lifecycle.
    """

    def __init__(self):
        self.blackboard = Blackboard()
        self.event_bus = EventBus()
        self.agents = {}
        self.scan_start_time = None
        self.scan_end_time = None
        self.event_log = []

        # Subscribe to all events for logging
        self.event_bus.subscribe("*", self._global_event_handler)

    async def _global_event_handler(self, event: dict):
        self.event_log.append(event)

    def _init_agents(self):
        """Initialize all agents and wire them to the Hive"""
        self.agents = {
            AgentRole.COMMANDER: CommanderAgent(self.blackboard, self.event_bus),
            AgentRole.SHADOW: ShadowAgent(self.blackboard, self.event_bus),
            AgentRole.HUNTER: HunterAgent(self.blackboard, self.event_bus),
            AgentRole.RED_TEAM: RedTeamAgent(self.blackboard, self.event_bus),
            AgentRole.ARCHITECT: ArchitectAgent(self.blackboard, self.event_bus),
            AgentRole.HISTORIAN: HistorianAgent(self.blackboard, self.event_bus),
        }

        # Register all agents with the Commander
        commander = self.agents[AgentRole.COMMANDER]
        for role, agent in self.agents.items():
            if role != AgentRole.COMMANDER:
                commander.register_agent(agent)

    async def scan(self, target: str, target_type: str = "url") -> dict:
        """
        Execute a full security assessment.

        This runs the complete pipeline:
          1. Commander builds HTN plan
          2. Shadow does reconnaissance
          3. Hunter discovers vulnerabilities
          4. Red Team verifies exploitability
          5. Architect generates remediations
          6. Historian records everything and produces report
        """
        self.scan_start_time = time.time()
        print(f"\n{'='*70}")
        print(f"  THREATSCAN HIVE — Full Security Assessment")
        print(f"  Target: {target} ({target_type})")
        print(f"{'='*70}\n")
        settings.print_status()

        # Initialize
        self._init_agents()
        scan_target = ScanTarget(target_type=target_type, value=target)
        await self.blackboard.set_fact("scan_target", target)
        await self.blackboard.set_fact("scan_target_type", target_type)

        commander = self.agents[AgentRole.COMMANDER]

        # Phase 1: Commander builds HTN
        print("▸ Phase 1: COMMANDER building Hierarchical Task Network...")
        htn = commander.build_htn(scan_target)
        htn_summary = commander.get_htn_summary()
        total_tasks = self._count_tasks(htn_summary)
        print(f"  ✓ HTN built: {total_tasks} tasks across {len(htn_summary.get('subtasks', []))} phases\n")

        # Phase 2: Shadow reconnaissance
        print("▸ Phase 2: SHADOW running reconnaissance...")
        shadow = self.agents[AgentRole.SHADOW]
        await shadow.run(max_loops=10)
        recon_data = await self.blackboard.get_fact("discovered_endpoints") or []
        tech = await self.blackboard.get_fact("detected_framework") or "unknown"
        subdomains = await self.blackboard.get_fact("subdomains") or []
        vuln_deps = await self.blackboard.get_fact("vulnerable_dependencies") or []
        print(f"  ✓ Framework: {tech}")
        print(f"  ✓ Subdomains: {len(subdomains)}")
        print(f"  ✓ Endpoints discovered: {len(recon_data)}")
        print(f"  ✓ Vulnerable dependencies: {len(vuln_deps)}")
        attack_surface = await self.blackboard.get_attack_surface()
        print(f"  ✓ Attack surface nodes: {len(attack_surface)}\n")

        # Phase 3: Hunter vulnerability discovery
        print("▸ Phase 3: HUNTER running vulnerability discovery...")
        hunter = self.agents[AgentRole.HUNTER]
        await hunter.run(max_loops=10)
        findings_pre_verify = await self.blackboard.get_findings()
        print(f"  ✓ Raw findings: {len(findings_pre_verify)}")
        for sev_name in ["critical", "high", "medium", "low"]:
            from threatscan.core.agent_framework import FindingSeverity
            sev = FindingSeverity(sev_name)
            count = len([f for f in findings_pre_verify if f.severity == sev])
            if count > 0:
                marker = "🔴" if sev_name == "critical" else "🟠" if sev_name == "high" else "🟡" if sev_name == "medium" else "🟢"
                print(f"    {marker} {sev_name.upper()}: {count}")
        print()

        # Phase 4: Red Team verification
        print("▸ Phase 4: RED TEAM adversarial verification...")
        redteam = self.agents[AgentRole.RED_TEAM]
        await redteam.run(max_loops=20)
        verified = redteam.verified_findings
        exploitable = [v for v in verified if v.get("exploitable")]
        print(f"  ✓ Findings verified: {len(verified)}")
        print(f"  ✓ Confirmed exploitable: {len(exploitable)}")
        for exp in exploitable:
            evasion = exp.get("evasion", {}).get("verdict", "unknown")
            print(f"    ⚔️  {exp.get('best_strategy', 'N/A')} — evasion: {evasion}")
        print()

        # Phase 5: Architect remediation
        print("▸ Phase 5: ARCHITECT generating remediations...")
        architect = self.agents[AgentRole.ARCHITECT]
        await architect.run(max_loops=20)
        patches = architect.patches_generated
        gates_passed = sum(1 for p in patches if p.get("all_gates_passed"))
        print(f"  ✓ Patches generated: {len(patches)}")
        print(f"  ✓ All validation gates passed: {gates_passed}/{len(patches)}\n")

        # Phase 6: Historian analysis & reporting
        print("▸ Phase 6: HISTORIAN recording & analyzing...")
        historian = self.agents[AgentRole.HISTORIAN]
        await historian.run(max_loops=5)
        report = historian.scan_report
        print(f"  ✓ Episodic memories stored: {len(historian.episodic_memory)}")
        print(f"  ✓ RL model updated: {sum(historian.bandit.pulls)} bandit pulls")
        print(f"  ✓ Threat intel correlations: {len(historian.threat_intel_cache)}")

        self.scan_end_time = time.time()
        duration = self.scan_end_time - self.scan_start_time

        # ── Final Summary ──
        summary = report.get("summary", {})
        risk = report.get("risk_score", 0)

        print(f"\n{'='*70}")
        print(f"  SCAN COMPLETE — {duration:.1f}s")
        print(f"{'='*70}")
        print(f"\n  ╔══════════════════════════════════════════╗")
        print(f"  ║  RISK SCORE: {risk:>5.1f} / 100                  ║")
        risk_bar = "█" * int(risk / 5) + "░" * (20 - int(risk / 5))
        risk_color = "CRITICAL" if risk > 75 else "HIGH" if risk > 50 else "MEDIUM" if risk > 25 else "LOW"
        print(f"  ║  [{risk_bar}]  {risk_color:<9} ║")
        print(f"  ╚══════════════════════════════════════════╝")

        print(f"\n  Findings:  {summary.get('total_findings', 0)} total "
              f"({summary.get('exploitable_findings', 0)} exploitable)")
        print(f"  Critical:  {summary.get('critical', 0)}  |  High: {summary.get('high', 0)}  "
              f"|  Medium: {summary.get('medium', 0)}  |  Low: {summary.get('low', 0)}")
        print(f"  Surface:   {summary.get('attack_surface_nodes', 0)} nodes mapped")
        print(f"  Intel:     {summary.get('threat_correlations', 0)} threat correlations")
        print(f"  Patches:   {len(patches)} generated ({gates_passed} validated)")

        if report.get("executive_summary"):
            print(f"\n  Executive Summary:")
            print(f"  {'─'*64}")
            for line in report["executive_summary"].split('\n')[:12]:
                print(f"  {line}")

        if report.get("recommendations_priority"):
            print(f"\n  Priority Remediation:")
            for rec in report["recommendations_priority"][:5]:
                print(f"    {rec}")

        if report.get("attack_chains"):
            print(f"\n  Attack Chains Detected:")
            for chain in report["attack_chains"]:
                print(f"    ⛓️  {chain['title']} (confidence: {chain['confidence']:.0%})")

        print(f"\n  Events logged: {len(self.event_log)}")
        print(f"{'='*70}\n")

        return {
            "report": report,
            "duration": duration,
            "htn": htn_summary,
            "patches": patches,
            "verified": verified,
            "events": len(self.event_log),
        }

    def _count_tasks(self, node: dict) -> int:
        count = 1
        for sub in node.get("subtasks", []):
            count += self._count_tasks(sub)
        return count


async def main():
    hive = ThreatScanHive()
    result = await hive.scan(
        target="https://api.example-fintech.com",
        target_type="url"
    )
    return result


if __name__ == "__main__":
    result = asyncio.run(main())
