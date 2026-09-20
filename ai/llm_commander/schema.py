"""Strict schema for LLM Incident Commander output.

The LLM only ever produces this document. It is validated before anything reads it, action
names outside ACTION_NAMES fail validation, and nothing here is executed: recommended actions are
turned into approval requests / policy-checked playbook steps elsewhere.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Must equal the keys of soar.playbooks.actions.ACTIONS (asserted in tests/test_llm_commander.py).
ACTION_NAMES = ("enrich_ioc", "notify_analyst", "collect_evidence", "create_case", "block_ip",
                "isolate_host", "disable_account")
ActionName = Literal["enrich_ioc", "notify_analyst", "collect_evidence", "create_case", "block_ip",
                     "isolate_host", "disable_account"]


class MitreSuggestion(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(max_length=16)
    name: str = Field(default="", max_length=128)
    tactic: str = Field(default="", max_length=64)
    confidence: float = Field(default=0.4, ge=0, le=1)
    evidence: str = Field(default="", max_length=500)


class RecommendedAction(BaseModel):
    model_config = ConfigDict(extra="ignore")
    action: ActionName
    target: str | None = Field(default=None, max_length=255)
    rationale: str = Field(default="", max_length=500)


class CommanderOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")
    summary: str = Field(min_length=1, max_length=3000)
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    mitre_techniques: list[MitreSuggestion] = Field(default_factory=list, max_length=10)
    evidence: list[str] = Field(default_factory=list, max_length=20)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list, max_length=10)
    requires_human_approval: bool = True

    @field_validator("evidence")
    @classmethod
    def _clip_evidence(cls, v: list[str]) -> list[str]:
        return [str(x)[:500] for x in v]


JSON_SHAPE = """{
  "summary": "2-4 sentence factual summary of what happened",
  "severity": "low | medium | high | critical",
  "confidence": 0.0,
  "mitre_techniques": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "confidence": 0.6, "evidence": "why"}],
  "evidence": ["short factual statements taken from the provided context"],
  "recommended_actions": [{"action": "one of: __ACTIONS__", "target": "ip/host/user or null", "rationale": "why"}],
  "requires_human_approval": true
}""".replace("__ACTIONS__", " | ".join(ACTION_NAMES))
