from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any

class Severity(str, Enum):
    P1 = "P1_CRITICAL"
    P2 = "P2_HIGH"
    P3 = "P3_MEDIUM"
    P4 = "P4_LOW"

class IncidentStatus(str, Enum):
    TRIGGERED = "TRIGGERED"
    TRIAGED = "TRIAGED"
    MITIGATING = "MITIGATING"
    RESOLVED = "RESOLVED"

@dataclass
class Alert:
    id: str
    timestamp: datetime
    service: str
    severity: Severity
    title: str
    message: str
    stack_trace: Optional[str] = None
    environment: str = "production"
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

@dataclass
class DeploymentEvent:
    id: str
    timestamp: datetime
    service: str
    commit_hash: str
    author: str
    description: str
    diff_summary: str
    changed_files: List[str] = field(default_factory=list)

@dataclass
class IncidentCluster:
    cluster_id: str
    created_at: datetime
    updated_at: datetime
    service: str
    primary_signature: str
    severity: Severity
    alerts: List[Alert] = field(default_factory=list)
    status: IncidentStatus = IncidentStatus.TRIGGERED
    velocity_alerts_per_min: float = 0.0

@dataclass
class MitigationPlaybook:
    id: str
    name: str
    description: str
    recommended_action: str
    automated_command: str
    risk_level: str

@dataclass
class TriageReport:
    incident_id: str
    generated_at: datetime
    service: str
    severity: Severity
    alert_count: int
    primary_root_cause: str
    confidence_score: float
    correlated_deployments: List[DeploymentEvent]
    recommended_playbook: MitigationPlaybook
    impact_summary: str
    markdown_postmortem: str
