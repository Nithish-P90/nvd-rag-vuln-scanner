# rag/nvd_schema.py
"""
Shared contract between NVD ingestion (ingestion/*.py) and retrieval (rag_nvd2.py).

Keeping both sides here guarantees documents and queries are embedded the
same way:
  - nomic-embed-text is trained with task prefixes; documents must be
    embedded as "search_document: ..." and queries as "search_query: ...".
    Without them similarity scores are compressed and noisy.
  - Documents carry plain-English CWE names so a natural-language finding
    ("buffer copy without checking size of input") lands near CVEs that only
    say "CWE-120" in their metadata.
"""

import re
from typing import Iterable, Optional

COLLECTION_NAME   = "nvd_threats_v2"     # prefixed + CWE-named documents
LEGACY_COLLECTION = "nvd_threats"        # original, unprefixed embeddings
EMBED_MODEL       = "nomic-embed-text"
DOC_PREFIX        = "search_document: "
QUERY_PREFIX      = "search_query: "

# NVD placeholders that are not real weaknesses.
NON_CWES = {"NVD-CWE-Other", "NVD-CWE-noinfo"}


# ─── CWE catalog ───────────────────────────────────────────
# id -> (name, one-line description written the way NVD describes impact)
CWE_INFO = {
    "CWE-20":   ("Improper Input Validation",
                 "input is not validated before use, allowing crafted input to trigger unexpected behavior"),
    "CWE-22":   ("Path Traversal",
                 "a user-controlled file path containing ../ sequences allows reading or writing arbitrary files"),
    "CWE-23":   ("Relative Path Traversal",
                 "relative path sequences in user input allow access to files outside the intended directory"),
    "CWE-59":   ("Link Following",
                 "symbolic links are followed allowing access to unintended files"),
    "CWE-73":   ("External Control of File Name or Path",
                 "attacker-controlled input determines which file is opened"),
    "CWE-77":   ("Command Injection",
                 "attacker input is used to build a command, allowing injection of arbitrary commands"),
    "CWE-78":   ("OS Command Injection",
                 "unsanitized input is passed to a shell or system call, allowing execution of arbitrary OS commands"),
    "CWE-79":   ("Cross-site Scripting",
                 "user input is reflected into a web page without encoding, allowing injection of arbitrary script"),
    "CWE-88":   ("Argument Injection",
                 "attacker input injects extra arguments into a command invocation"),
    "CWE-89":   ("SQL Injection",
                 "user input is concatenated into an SQL query, allowing execution of arbitrary SQL commands"),
    "CWE-90":   ("LDAP Injection",
                 "user input is inserted into an LDAP query without neutralization"),
    "CWE-94":   ("Code Injection",
                 "attacker-controlled data is evaluated as code, allowing arbitrary code execution"),
    "CWE-95":   ("Eval Injection",
                 "user input reaches an eval-style function, allowing arbitrary code execution"),
    "CWE-119":  ("Improper Restriction of Operations within the Bounds of a Memory Buffer",
                 "memory is read or written outside the bounds of a buffer, causing memory corruption"),
    "CWE-120":  ("Buffer Copy without Checking Size of Input",
                 "data is copied into a fixed-size buffer without checking its length, causing a buffer overflow"),
    "CWE-121":  ("Stack-based Buffer Overflow",
                 "a stack buffer is overflowed, allowing denial of service or arbitrary code execution"),
    "CWE-122":  ("Heap-based Buffer Overflow",
                 "a heap buffer is overflowed, allowing denial of service or arbitrary code execution"),
    "CWE-125":  ("Out-of-bounds Read",
                 "data is read past the end of a buffer, causing information disclosure or a crash"),
    "CWE-131":  ("Incorrect Calculation of Buffer Size",
                 "the buffer size is miscalculated leading to an overflow"),
    "CWE-134":  ("Use of Externally-Controlled Format String",
                 "user input is used as a printf-style format string, allowing memory read/write and code execution"),
    "CWE-190":  ("Integer Overflow or Wraparound",
                 "an integer calculation wraps around, leading to an undersized allocation and buffer overflow"),
    "CWE-191":  ("Integer Underflow",
                 "an integer subtraction underflows producing a huge length value"),
    "CWE-200":  ("Exposure of Sensitive Information",
                 "sensitive information is exposed to an unauthorized actor"),
    "CWE-209":  ("Information Exposure Through Error Message",
                 "error messages reveal sensitive internal details"),
    "CWE-250":  ("Execution with Unnecessary Privileges",
                 "code runs with more privileges than needed"),
    "CWE-256":  ("Plaintext Storage of a Password",
                 "passwords are stored in plaintext"),
    "CWE-259":  ("Use of Hard-coded Password",
                 "a hard-coded password allows attackers to authenticate"),
    "CWE-269":  ("Improper Privilege Management",
                 "privileges are not properly assigned or checked, allowing privilege escalation"),
    "CWE-284":  ("Improper Access Control",
                 "access to a resource is not properly restricted"),
    "CWE-285":  ("Improper Authorization",
                 "authorization checks are missing or incorrect"),
    "CWE-287":  ("Improper Authentication",
                 "authentication can be bypassed, allowing unauthenticated access"),
    "CWE-295":  ("Improper Certificate Validation",
                 "TLS certificates are not validated, allowing man-in-the-middle attacks"),
    "CWE-306":  ("Missing Authentication for Critical Function",
                 "a critical function can be invoked without authentication"),
    "CWE-311":  ("Missing Encryption of Sensitive Data",
                 "sensitive data is transmitted or stored without encryption"),
    "CWE-312":  ("Cleartext Storage of Sensitive Information",
                 "sensitive information is stored in cleartext"),
    "CWE-319":  ("Cleartext Transmission of Sensitive Information",
                 "sensitive data is sent over an unencrypted channel"),
    "CWE-321":  ("Use of Hard-coded Cryptographic Key",
                 "a hard-coded cryptographic key allows decryption by attackers"),
    "CWE-326":  ("Inadequate Encryption Strength",
                 "encryption is too weak to protect the data"),
    "CWE-327":  ("Use of a Broken or Risky Cryptographic Algorithm",
                 "a weak algorithm such as MD5, SHA1, DES or RC4 is used, allowing attackers to break the protection"),
    "CWE-330":  ("Use of Insufficiently Random Values",
                 "predictable random values allow attackers to guess secrets"),
    "CWE-338":  ("Use of Cryptographically Weak PRNG",
                 "a non-cryptographic random number generator is used for security-sensitive values"),
    "CWE-352":  ("Cross-Site Request Forgery",
                 "requests are not verified as intentional, allowing attackers to perform actions as the victim"),
    "CWE-362":  ("Race Condition",
                 "concurrent access to a shared resource without proper synchronization causes a race condition"),
    "CWE-367":  ("Time-of-check Time-of-use Race Condition",
                 "a resource changes between the check and its use"),
    "CWE-399":  ("Resource Management Errors",
                 "resources are mismanaged, allowing denial of service"),
    "CWE-400":  ("Uncontrolled Resource Consumption",
                 "resource consumption is not limited, allowing denial of service"),
    "CWE-401":  ("Missing Release of Memory after Effective Lifetime",
                 "memory is not freed, causing a memory leak and denial of service"),
    "CWE-415":  ("Double Free",
                 "memory is freed twice, corrupting the heap and allowing code execution"),
    "CWE-416":  ("Use After Free",
                 "memory is used after it has been freed, allowing denial of service or arbitrary code execution"),
    "CWE-434":  ("Unrestricted Upload of File with Dangerous Type",
                 "dangerous file types can be uploaded and executed"),
    "CWE-457":  ("Use of Uninitialized Variable",
                 "an uninitialized variable is used"),
    "CWE-476":  ("NULL Pointer Dereference",
                 "a NULL pointer is dereferenced, causing a crash and denial of service"),
    "CWE-502":  ("Deserialization of Untrusted Data",
                 "untrusted data is deserialized, allowing arbitrary code execution"),
    "CWE-522":  ("Insufficiently Protected Credentials",
                 "credentials are stored or transmitted insecurely"),
    "CWE-532":  ("Insertion of Sensitive Information into Log File",
                 "sensitive data is written to log files"),
    "CWE-601":  ("Open Redirect",
                 "a user-controlled URL redirect allows phishing"),
    "CWE-611":  ("XML External Entity Reference",
                 "XML external entities are processed, allowing file disclosure or SSRF"),
    "CWE-674":  ("Uncontrolled Recursion",
                 "unbounded recursion exhausts the stack"),
    "CWE-732":  ("Incorrect Permission Assignment for Critical Resource",
                 "a critical resource has overly permissive permissions"),
    "CWE-770":  ("Allocation of Resources Without Limits",
                 "resources are allocated without limits, allowing denial of service"),
    "CWE-772":  ("Missing Release of Resource after Effective Lifetime",
                 "a resource is never released, causing exhaustion"),
    "CWE-787":  ("Out-of-bounds Write",
                 "data is written past the end of a buffer, causing memory corruption and code execution"),
    "CWE-798":  ("Use of Hard-coded Credentials",
                 "hard-coded credentials allow attackers to gain access"),
    "CWE-824":  ("Access of Uninitialized Pointer",
                 "an uninitialized pointer is dereferenced"),
    "CWE-829":  ("Inclusion of Functionality from Untrusted Control Sphere",
                 "code or components are loaded from an untrusted source"),
    "CWE-835":  ("Infinite Loop",
                 "a loop with an unreachable exit condition causes denial of service"),
    "CWE-862":  ("Missing Authorization",
                 "an action is performed without checking authorization"),
    "CWE-863":  ("Incorrect Authorization",
                 "the authorization check is incorrect, allowing access bypass"),
    "CWE-908":  ("Use of Uninitialized Resource",
                 "an uninitialized resource is used"),
    "CWE-918":  ("Server-Side Request Forgery",
                 "the server fetches an attacker-controlled URL, allowing access to internal services"),
    "CWE-1321": ("Prototype Pollution",
                 "attacker input modifies object prototype attributes"),
    "CWE-1427": ("Prompt Injection",
                 "untrusted input is placed into an LLM prompt, allowing instructions to be overridden"),
}

# Groups of CWEs that describe the same root cause at different
# abstraction levels. NVD labels the same bug class inconsistently
# (CWE-119 vs CWE-120 vs CWE-787), so retrieval treats a group as related.
CWE_GROUPS = [
    {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-131", "CWE-787", "CWE-805", "CWE-806"},
    {"CWE-119", "CWE-125", "CWE-126", "CWE-127"},
    {"CWE-190", "CWE-191", "CWE-189", "CWE-680", "CWE-681", "CWE-128", "CWE-122"},
    {"CWE-416", "CWE-415", "CWE-825", "CWE-763", "CWE-761"},
    {"CWE-476", "CWE-690", "CWE-824"},
    {"CWE-457", "CWE-908", "CWE-824"},
    {"CWE-134"},
    {"CWE-362", "CWE-367", "CWE-366", "CWE-364"},
    {"CWE-77", "CWE-78", "CWE-88"},
    {"CWE-94", "CWE-95", "CWE-77"},
    {"CWE-89", "CWE-943", "CWE-564"},
    {"CWE-79", "CWE-80", "CWE-87"},
    {"CWE-22", "CWE-23", "CWE-35", "CWE-36", "CWE-73", "CWE-59"},
    {"CWE-502"},
    {"CWE-611", "CWE-776", "CWE-827"},
    {"CWE-918"},
    {"CWE-798", "CWE-259", "CWE-321", "CWE-256", "CWE-522"},
    {"CWE-287", "CWE-306", "CWE-288", "CWE-290"},
    {"CWE-284", "CWE-285", "CWE-862", "CWE-863", "CWE-639", "CWE-269"},
    {"CWE-327", "CWE-326", "CWE-328", "CWE-916"},
    {"CWE-330", "CWE-338"},
    {"CWE-295", "CWE-297"},
    {"CWE-400", "CWE-770", "CWE-399", "CWE-835", "CWE-674"},
    {"CWE-401", "CWE-772", "CWE-404", "CWE-399"},
    {"CWE-200", "CWE-209", "CWE-532", "CWE-312", "CWE-319"},
    {"CWE-352"},
    {"CWE-601"},
    {"CWE-1427", "CWE-77"},
]


def normalize_cwe(cwe: Optional[str]) -> Optional[str]:
    """'120', 'cwe-120', 'CWE-120: Buffer...' -> 'CWE-120'."""
    if not cwe:
        return None
    m = re.search(r"(\d+)", str(cwe))
    if not m or "NVD-CWE" in str(cwe):
        return None
    return f"CWE-{int(m.group(1))}"


def cwe_family(cwes: Iterable[str]) -> list:
    """The given CWEs plus every CWE sharing a root-cause group with them."""
    seeds  = [c for c in (normalize_cwe(c) for c in cwes) if c]
    family = list(dict.fromkeys(seeds))
    for group in CWE_GROUPS:
        if group.intersection(seeds):
            family.extend(sorted(group - set(family)))
    return family


def cwe_label(cwe: str) -> str:
    name = CWE_INFO.get(cwe, (None,))[0]
    return f"{cwe} ({name})" if name else cwe


def normalize_payload(payload: dict) -> dict:
    """
    Repairs payloads written by the original ingestion, which stored
    nvdlib's score tuple in the wrong order (cvss_score="HIGH", severity=7.5).
    """
    p = dict(payload)
    sev, score = p.get("severity"), p.get("cvss_score")
    if isinstance(sev, (int, float)) and not isinstance(score, (int, float)):
        p["severity"], p["cvss_score"] = score, sev
    p["severity"] = str(p.get("severity") or "UNKNOWN").upper()
    try:
        p["cvss_score"] = float(p["cvss_score"]) if p.get("cvss_score") is not None else None
    except (TypeError, ValueError):
        p["cvss_score"] = None
    p["cwe_ids"] = list(dict.fromkeys(c for c in (p.get("cwe_ids") or []) if c))
    return p


def document_text(payload: dict) -> str:
    """Text embedded for one CVE (without the nomic prefix)."""
    text  = payload.get("description", "").strip()
    named = [cwe_label(c) for c in payload.get("cwe_ids", []) if c not in NON_CWES]
    if named:
        text += " Weakness: " + "; ".join(named) + "."
    return text
