from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any
import uuid

@dataclass
class Vulnerability:
    """Класс уязвимости (согласно диаграмме классов)"""
    vuln_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = "Unknown"
    severity: int = 0
    endpoint: str = ""
    description: str = ""
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id, "name": self.name, "severity": self.severity,
            "endpoint": self.endpoint, "description": self.description, "evidence": self.evidence
        }

@dataclass
class ScanSession:
    """Класс сессии сканирования (согласно диаграмме классов)"""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    start_time: datetime = field(default_factory=datetime.now)
    target_url: str = ""
    status: str = "INITIALIZED"
    findings: List[Vulnerability] = field(default_factory=list)

    def add_finding(self, vuln: Vulnerability):
        self.findings.append(vuln)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "id": self.session_id,
            "start_time": self.start_time.isoformat(),
            "total_findings": len(self.findings),
            "status": self.status
        }