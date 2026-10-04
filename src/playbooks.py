from src.models import IncidentCluster, MitigationPlaybook

PLAYBOOK_CATALOG = {
    "ROLLBACK": MitigationPlaybook("PB-ROLLBACK", "Automated Service Rollback", "Rolls back to previous container release.", "Initiate canary rollback.", "kubectl rollout undo deployment/{service} -n production", "MEDIUM"),
    "SCALE_UP": MitigationPlaybook("PB-SCALE-UP", "Horizontal Pod Auto-Scaling", "Scales replica pool to absorb load.", "Scale replicas by 100%.", "kubectl scale deployment/{service} --replicas={replicas} -n production", "LOW"),
    "CIRCUIT_BREAKER": MitigationPlaybook("PB-CIRCUIT-BREAKER", "Downstream Circuit Breaker", "Isolates failing downstream dependency.", "Trip circuit breaker to fallback response.", "consul-kv set services/{service}/circuit_breaker_enabled true", "MEDIUM"),
    "INVESTIGATE": MitigationPlaybook("PB-INVESTIGATE", "On-Call Escalation", "Presents diagnostic summary to on-call.", "Page primary on-call engineer.", "pagerduty-cli trigger --service {service}", "LOW")
}

class PlaybookRecommender:
    @staticmethod
    def select_playbook(cluster: IncidentCluster, has_correlated_deployment: bool, top_confidence: float) -> MitigationPlaybook:
        text = " ".join([f"{a.title} {a.message}" for a in cluster.alerts]).lower()
        if has_correlated_deployment and top_confidence >= 0.70:
            pb = PLAYBOOK_CATALOG["ROLLBACK"]
            return MitigationPlaybook(pb.id, pb.name, pb.description, pb.recommended_action, pb.automated_command.format(service=cluster.service), pb.risk_level)
        if any(term in text for term in ["timeout", "connection refused", "504"]):
            pb = PLAYBOOK_CATALOG["CIRCUIT_BREAKER"]
            return MitigationPlaybook(pb.id, pb.name, pb.description, pb.recommended_action, pb.automated_command.format(service=cluster.service), pb.risk_level)
        if any(term in text for term in ["oom", "out of memory", "cpu throttle"]):
            pb = PLAYBOOK_CATALOG["SCALE_UP"]
            return MitigationPlaybook(pb.id, pb.name, pb.description, pb.recommended_action, pb.automated_command.format(service=cluster.service, replicas=10), pb.risk_level)
        pb = PLAYBOOK_CATALOG["INVESTIGATE"]
        return MitigationPlaybook(pb.id, pb.name, pb.description, pb.recommended_action, pb.automated_command.format(service=cluster.service), pb.risk_level)
