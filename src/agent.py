from datetime import datetime
from typing import List, Optional
from src.models import Alert, DeploymentEvent, IncidentCluster, TriageReport, IncidentStatus
from src.clusterer import AlertClusterer
from src.correlator import DeploymentCorrelator
from src.playbooks import PlaybookRecommender

class IncidentTriagingAgent:
    def __init__(self, time_window_minutes: int = 15, lookback_hours: int = 4):
        self.clusterer = AlertClusterer(time_window_minutes=time_window_minutes)
        self.correlator = DeploymentCorrelator(max_lookback_hours=lookback_hours)
        self.known_deployments: List[DeploymentEvent] = []

    def register_deployment(self, deployment: DeploymentEvent):
        self.known_deployments.append(deployment)

    def process_alert(self, alert: Alert) -> IncidentCluster:
        return self.clusterer.ingest_alert(alert)

    def evaluate_incident(self, cluster_id: str) -> Optional[TriageReport]:
        cluster = self.clusterer.clusters.get(cluster_id)
        if not cluster:
            return None
        corr_results = self.correlator.correlate(cluster, self.known_deployments)
        has_corr = len(corr_results) > 0
        top_conf = corr_results[0][1] if has_corr else 0.0

        if has_corr and top_conf >= 0.70:
            top_d, score, rat = corr_results[0]
            root_cause = f"Regression in deployment {top_d.commit_hash[:7]} ('{top_d.description}'). {rat}"
        else:
            root_cause = f"Infrastructure or operational anomaly in service '{cluster.service}'."
            top_conf = max(top_conf, 0.40)

        playbook = PlaybookRecommender.select_playbook(cluster, has_corr, top_conf)
        impact = f"Service '{cluster.service}' degraded. Total alerts: {len(cluster.alerts)}. Severity: {cluster.severity.value}."
        postmortem = f"# Incident Report {cluster.cluster_id}\nService: {cluster.service}\nRoot Cause: {root_cause}\nRecommended: {playbook.name}"
        cluster.status = IncidentStatus.TRIAGED

        return TriageReport(
            cluster.cluster_id, datetime.utcnow(), cluster.service, cluster.severity,
            len(cluster.alerts), root_cause, top_conf, [d for d, _, _ in corr_results],
            playbook, impact, postmortem
        )
