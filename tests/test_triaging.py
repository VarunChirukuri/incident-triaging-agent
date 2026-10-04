import sys, unittest
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models import Alert, DeploymentEvent, Severity
from src.fingerprint import ErrorFingerprinter
from src.clusterer import AlertClusterer
from src.correlator import DeploymentCorrelator
from src.agent import IncidentTriagingAgent

class TestTriaging(unittest.TestCase):
    def test_fingerprinting(self):
        m1 = "Db timeout: user=123 txn=4f9b2d30-8a12-4e4b-9e23-7fa51239ab4e"
        m2 = "Db timeout: user=999 txn=a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
        self.assertEqual(ErrorFingerprinter.normalize_message(m1), ErrorFingerprinter.normalize_message(m2))

    def test_clustering(self):
        c = AlertClusterer()
        t = datetime(2026, 10, 4, 10, 0, 0)
        a1 = Alert("1", t, "auth", Severity.P2, "AuthFailed", "Token validation failed for session id=101")
        a2 = Alert("2", t + timedelta(seconds=10), "auth", Severity.P1, "AuthFailed", "Token validation failed for session id=202")
        cluster = c.ingest_alert(a1)
        cluster = c.ingest_alert(a2)
        self.assertEqual(len(cluster.alerts), 2)
        self.assertEqual(cluster.severity, Severity.P1)

    def test_correlation_and_agent(self):
        agent = IncidentTriagingAgent()
        t = datetime(2026, 10, 4, 10, 0, 0)
        d = DeploymentEvent("d1", t - timedelta(minutes=15), "payments", "abc1234", "dev", "Upgrade gateway", "diff", ["src/gateway.py"])
        agent.register_deployment(d)
        a = Alert("a1", t, "payments", Severity.P1, "ChargeFail", "Failed in gateway", stack_trace="File 'src/gateway.py', line 10")
        cluster = agent.process_alert(a)
        report = agent.evaluate_incident(cluster.cluster_id)
        self.assertIsNotNone(report)
        self.assertEqual(report.recommended_playbook.id, "PB-ROLLBACK")

if __name__ == "__main__":
    unittest.main()
