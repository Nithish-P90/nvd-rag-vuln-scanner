# tests/test_categorization_agent.py
"""
Unit tests for the enhanced CategorizationAgent:
  - STRIDE threat classification
  - MITRE ATLAS technique mapping for AI/ML-related threats
  - Non-applicable ATLAS for ordinary software bugs
  - Preservation and strict separation of CWE and CVE fields
  - Deduplication, normalization, and ranking behavior
  - Downstream compatibility with ValidationAgent and PipelineState
"""

import sys
import unittest
from pathlib import Path

# Add project root and agents to sys.path
_ROOT = Path(__file__).resolve().parent.parent
_AGENTS_DIR = _ROOT / "agents"
_RAG_DIR = _ROOT / "rag"

if str(_AGENTS_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTS_DIR))
if str(_RAG_DIR) not in sys.path:
    sys.path.insert(0, str(_RAG_DIR))

from orchestrator2 import CategorizationAgent, PipelineState


class TestCategorizationAgent(unittest.TestCase):

    def setUp(self):
        self.agent = CategorizationAgent()

    def test_ordinary_vulnerability_stride_and_atlas(self):
        """Test standard C buffer overflow: STRIDE assigned, ATLAS is Not applicable."""
        state = PipelineState(
            code="void copy_user(char *src) { char buf[64]; strcpy(buf, src); }",
            language="c",
            forensics_signals=[{
                "vulnerability_type": "buffer overflow",
                "affected_code": "strcpy(buf, src)",
                "cwe_id": "CWE-120",
                "confidence": "HIGH"
            }],
            cve_matches=[{
                "cve_id": "CVE-2026-6691",
                "severity": "CRITICAL",
                "cwe_ids": ["CWE-120"],
                "description": "Buffer overflow in string copy allows arbitrary code execution"
            }]
        )

        # Test normalization logic directly
        raw_llm_findings = [{
            "category": "Buffer Overflow",
            "severity": "CRITICAL",
            "cwe_ids": ["CWE-120", "CWE-787"],
            "evidence": "strcpy called with unbounded input into fixed buffer",
            "related_cves": ["CVE-2026-6691"],
            "stride": ["Tampering", "Elevation of Privilege", "Denial of Service"],
            "mitre_atlas": ["Not applicable"]
        }]

        normalized = self.agent._normalize_and_deduplicate(raw_llm_findings, state.cve_matches, state.code)
        self.assertEqual(len(normalized), 1)
        finding = normalized[0]

        # Verify category and severity
        self.assertEqual(finding["category"], "Buffer Overflow")
        self.assertEqual(finding["severity"], "CRITICAL")

        # Verify STRIDE
        self.assertIn("Tampering", finding["stride"])
        self.assertIn("Elevation of Privilege", finding["stride"])

        # Verify MITRE ATLAS is Not applicable for standard C vulnerability
        self.assertEqual(finding["mitre_atlas"], ["Not applicable"])

        # Verify CWE / CVE preservation
        self.assertIn("CWE-120", finding["cwe_ids"])
        self.assertIn("CVE-2026-6691", finding["related_cves"])

    def test_aiml_threat_prompt_injection(self):
        """Test AI/ML prompt injection mapping to verified MITRE ATLAS AML.T0051."""
        code = "response = ollama.chat(model='llama3', messages=[{'role': 'user', 'content': untrusted_user_prompt}])"
        raw_findings = [{
            "category": "Prompt Injection",
            "severity": "HIGH",
            "cwe_ids": ["CWE-1426"],
            "evidence": "Direct concatenation of untrusted input into LLM prompt without sanitization",
            "related_cves": [],
            "stride": ["Tampering", "Elevation of Privilege"],
            "mitre_atlas": ["AML.T0051: LLM Prompt Injection"]
        }]

        normalized = self.agent._normalize_and_deduplicate(raw_findings, [], code)
        self.assertEqual(len(normalized), 1)
        finding = normalized[0]

        # Verify MITRE ATLAS verified technique mapping
        self.assertIn("AML.T0051: LLM Prompt Injection", finding["mitre_atlas"])
        self.assertIn("Tampering", finding["stride"])

    def test_aiml_threat_model_deserialization(self):
        """Test PyTorch/Pickle model deserialization mapping to AML.T0010: ML Model Backdooring."""
        code = "import torch\nweights = torch.load('model_weights.pt')"
        raw_findings = [{
            "category": "Insecure ML Model Deserialization",
            "severity": "CRITICAL",
            "cwe_ids": ["CWE-502"],
            "evidence": "torch.load loading untrusted model weights using pickle deserialization",
            "related_cves": [],
            "stride": ["Elevation of Privilege", "Tampering"],
            "mitre_atlas": ["AML.T0010: ML Model Backdooring"]
        }]

        normalized = self.agent._normalize_and_deduplicate(raw_findings, [], code)
        self.assertEqual(len(normalized), 1)
        finding = normalized[0]

        self.assertIn("AML.T0010: ML Model Backdooring", finding["mitre_atlas"])
        self.assertIn("Elevation of Privilege", finding["stride"])

    def test_cwe_cve_strict_separation(self):
        """Ensure CWEs mistakenly placed in related_cves are moved to cwe_ids and not treated as CVEs."""
        raw_findings = [{
            "category": "SQL Injection",
            "severity": "HIGH",
            "cwe_ids": [],
            "evidence": "Raw SQL concatenation",
            "related_cves": ["CWE-89", "CVE-2023-1234"],  # CWE-89 mistakenly in CVEs
            "stride": [],
            "mitre_atlas": []
        }]

        cve_matches = [{"cve_id": "CVE-2023-1234", "severity": "HIGH", "cwe_ids": ["CWE-89"]}]
        normalized = self.agent._normalize_and_deduplicate(raw_findings, cve_matches, "cursor.execute(query)")

        finding = normalized[0]
        # CWE-89 must be in cwe_ids
        self.assertIn("CWE-89", finding["cwe_ids"])
        # Only valid CVE in related_cves
        self.assertEqual(finding["related_cves"], ["CVE-2023-1234"])
        self.assertNotIn("CWE-89", finding["related_cves"])

    def test_deduplication_and_severity_ranking(self):
        """Test merging duplicate categories and sorting CRITICAL before MEDIUM."""
        raw_findings = [
            {
                "category": "Buffer Overflow",
                "severity": "MEDIUM",
                "cwe_ids": ["CWE-120"],
                "evidence": "strcpy call 1",
                "related_cves": [],
                "stride": ["Tampering"],
                "mitre_atlas": []
            },
            {
                "category": "Buffer Overflow",
                "severity": "CRITICAL",  # Higher severity should upgrade
                "cwe_ids": ["CWE-787"],
                "evidence": "strcpy call 2",
                "related_cves": [],
                "stride": ["Elevation of Privilege"],
                "mitre_atlas": []
            },
            {
                "category": "Information Leak",
                "severity": "LOW",
                "cwe_ids": ["CWE-200"],
                "evidence": "print statement",
                "related_cves": [],
                "stride": ["Information Disclosure"],
                "mitre_atlas": []
            }
        ]

        normalized = self.agent._normalize_and_deduplicate(raw_findings, [])
        # Should be merged into 2 findings
        self.assertEqual(len(normalized), 2)
        # First must be CRITICAL Buffer Overflow
        self.assertEqual(normalized[0]["category"], "Buffer Overflow")
        self.assertEqual(normalized[0]["severity"], "CRITICAL")
        self.assertIn("CWE-120", normalized[0]["cwe_ids"])
        self.assertIn("CWE-787", normalized[0]["cwe_ids"])
        self.assertIn("Tampering", normalized[0]["stride"])
        self.assertIn("Elevation of Privilege", normalized[0]["stride"])

    def test_empty_input_graceful_handling(self):
        """Test that missing/empty inputs produce clean empty findings list."""
        state = PipelineState(code="")
        result_state = self.agent.run(state)
        self.assertEqual(result_state.ranked_findings, [])
        self.assertIn("CategorizationAgent", result_state.steps_completed)


if __name__ == "__main__":
    unittest.main()
