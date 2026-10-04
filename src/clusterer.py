from datetime import timedelta
from typing import Dict, List, Optional
from src.models import Alert, IncidentCluster, Severity, IncidentStatus
from src.fingerprint import ErrorFingerprinter

class AlertClusterer:
    def __init__(self, time_window_minutes: int = 15):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.clusters: Dict[str, IncidentCluster] = {}

    def ingest_alert(self, alert: Alert) -> IncidentCluster:
        sig = ErrorFingerprinter.compute_signature(
            service=alert.service,
            title=alert.title,
            message=alert.message,
            stack_trace=alert.stack_trace
        )
        matched_cluster = None
        for cluster in self.clusters.values():
            if cluster.service == alert.service and cluster.primary_signature == sig:
                if alert.timestamp - cluster.updated_at <= self.time_window:
                    matched_cluster = cluster
                    break

        if matched_cluster:
            matched_cluster.alerts.append(alert)
            matched_cluster.updated_at = max(matched_cluster.updated_at, alert.timestamp)
            severities = [a.severity for a in matched_cluster.alerts]
            if Severity.P1 in severities:
                matched_cluster.severity = Severity.P1
            elif Severity.P2 in severities:
                matched_cluster.severity = Severity.P2
            elif Severity.P3 in severities:
                matched_cluster.severity = Severity.P3
            else:
                matched_cluster.severity = Severity.P4

            span = max((matched_cluster.updated_at - matched_cluster.created_at).total_seconds(), 1.0)
            matched_cluster.velocity_alerts_per_min = (len(matched_cluster.alerts) / span) * 60.0
            return matched_cluster
        else:
            cid = f"INC-{alert.service.upper()}-{sig[-6:]}"
            c = IncidentCluster(
                cluster_id=cid,
                created_at=alert.timestamp,
                updated_at=alert.timestamp,
                service=alert.service,
                primary_signature=sig,
                severity=alert.severity,
                alerts=[alert],
                status=IncidentStatus.TRIGGERED,
                velocity_alerts_per_min=1.0
            )
            self.clusters[cid] = c
            return c
