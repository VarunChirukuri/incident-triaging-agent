from datetime import timedelta
from typing import List, Tuple
from src.models import IncidentCluster, DeploymentEvent

class DeploymentCorrelator:
    def __init__(self, max_lookback_hours: int = 4):
        self.max_lookback = timedelta(hours=max_lookback_hours)

    def correlate(self, cluster: IncidentCluster, deployments: List[DeploymentEvent]) -> List[Tuple[DeploymentEvent, float, str]]:
        results = []
        cluster_time = cluster.created_at
        for deploy in deployments:
            if deploy.service.lower() != cluster.service.lower():
                continue
            time_diff = (cluster_time - deploy.timestamp).total_seconds()
            if time_diff < -120 or time_diff > self.max_lookback.total_seconds():
                continue
            score = 0.5
            rationale = [f"Deployed to '{deploy.service}' {int(time_diff / 60)}m prior to incident."]
            if 0 <= time_diff <= 1800:
                score += 0.25
                rationale.append("Temporal proximity <=30m.")
            trace_content = " ".join([a.stack_trace or "" for a in cluster.alerts]).lower()
            matches = [f.split("/")[-1].lower() for f in deploy.changed_files if f.split("/")[-1].lower() in trace_content]
            if matches:
                score += 0.25
                rationale.append(f"Stack trace matches changed file(s): {', '.join(matches)}")
            results.append((deploy, min(round(score, 2), 0.99), " ".join(rationale)))
        results.sort(key=lambda x: x[1], reverse=True)
        return results
