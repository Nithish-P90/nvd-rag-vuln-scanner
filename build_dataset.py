# finetune/build_dataset.py
"""
Builds the Validation Agent finetuning dataset from:
  - Manual examples       (hand-crafted, high quality)
  - PrimeVul              (C/C++ vulnerable functions with CVE/CWE labels)
  - BigVul                (C/C++ vulnerable functions from open source projects)
  - Juliet Test Suite     (NIST synthetic C/C++ good/bad pairs per CWE)
  - Devign                (real-world C functions from Linux/FFmpeg/Chrome)
  - SecurityEval          (Python-specific vulnerability samples)
  - CVEFixes              (real Python CVE before/after patches)

Expected file locations:
  finetune/data/primevul/primevul_train.json
  finetune/data/bigvul/bigvul.csv
  finetune/data/juliet/                        (folder of .c/.java files)
  finetune/data/devign/devign.json
  finetune/data/securityeval/dataset.json
  finetune/data/cvefixes/CVEfixes.db

Run:
  python build_dataset.py                  # full build with LLM reasoning
  python build_dataset.py --no-llm         # fast build without LLM reasoning
  python build_dataset.py --verify-only    # check which datasets are present
  python build_dataset.py --stats-only     # show stats on existing dataset
"""

import json
import csv
import re
import random
import hashlib
import argparse
from pathlib import Path
from collections import Counter

# sys.maxsize overflows the C long csv.field_size_limit uses on Windows;
# 2**31 - 1 is the largest value safe on every platform.
csv.field_size_limit(2**31 - 1)

# ─── Config ────────────────────────────────────────────────
BASE_DIR        = Path(__file__).resolve().parent
DATA_DIR        = BASE_DIR / "data"
OUTPUT_FILE     = BASE_DIR / "validation_agent_dataset.json"
SPLIT_FILE      = BASE_DIR / "dataset_splits.json"
RANDOM_SEED     = 42
MAX_CODE_LENGTH = 1200
MIN_CODE_LENGTH = 30
OLLAMA_LLM      = "llama3.2"

SAMPLE_LIMITS = {
    "primevul_confirmed":       300,
    "primevul_false_positive":  200,
    "bigvul_confirmed":         300,
    "juliet_confirmed":         200,
    "juliet_false_positive":    300,
    "devign_needs_context":     200, # include all
    "cvefixes_confirmed":       200,
    "cvefixes_false_positive":  200,
    "securityeval":             None,
}

random.seed(RANDOM_SEED)

# ─── CWE metadata ──────────────────────────────────────────
CWE_META = {
    "CWE-119": ("Buffer Overflow",           "memory copy without bounds check"),
    "CWE-120": ("Buffer Copy Overflow",      "strcpy/strcat without bounds check"),
    "CWE-121": ("Stack Buffer Overflow",     "stack-based buffer overflow"),
    "CWE-122": ("Heap Buffer Overflow",      "heap-based buffer overflow"),
    "CWE-125": ("Out-of-Bounds Read",        "read beyond buffer boundary"),
    "CWE-787": ("Out-of-Bounds Write",       "write beyond buffer boundary"),
    "CWE-416": ("Use After Free",            "memory used after free()"),
    "CWE-415": ("Double Free",               "memory freed twice"),
    "CWE-476": ("NULL Dereference",          "null pointer dereference"),
    "CWE-190": ("Integer Overflow",          "integer arithmetic overflow"),
    "CWE-191": ("Integer Underflow",         "integer arithmetic underflow"),
    "CWE-134": ("Format String",             "user-controlled format string"),
    "CWE-362": ("Race Condition",            "concurrent access without sync"),
    "CWE-78":  ("Command Injection",         "unsanitized input to system call"),
    "CWE-89":  ("SQL Injection",             "unsanitized input in SQL query"),
    "CWE-79":  ("XSS",                       "unsanitized input in HTML output"),
    "CWE-22":  ("Path Traversal",            "unsanitized path component"),
    "CWE-327": ("Weak Cryptography",         "broken or weak crypto algorithm"),
    "CWE-338": ("Weak PRNG",                 "non-cryptographic RNG"),
    "CWE-295": ("SSL Verification Disabled", "certificate verification disabled"),
    "CWE-502": ("Insecure Deserialization",  "deserialization of untrusted data"),
    "CWE-798": ("Hardcoded Credentials",     "credentials hardcoded in source"),
    "CWE-259": ("Hardcoded Password",        "password hardcoded in source"),
    "CWE-20":  ("Improper Input Validation", "missing or insufficient input validation"),
    "CWE-400": ("Resource Exhaustion",       "uncontrolled resource consumption"),
    "CWE-918": ("SSRF",                      "server-side request forgery"),
    "CWE-611": ("XXE",                       "XML external entity injection"),
    "CWE-94":  ("Code Injection",            "user input executed as code"),
    "CWE-287": ("Improper Authentication",   "missing or broken authentication"),
    "CWE-862": ("Missing Authorization",     "missing authorization check"),
}


# ─── Code helpers ──────────────────────────────────────────

def clean_code(code: str) -> str:
    """Normalize whitespace, remove null bytes, truncate long functions."""
    if not code:
        return ""
    code = code.replace("\x00", "").strip()
    if len(code) > MAX_CODE_LENGTH:
        code = code[:MAX_CODE_LENGTH] + "\n// ... (truncated)"
    return code


def is_valid_code(code: str) -> bool:
    """Filter out trivially short, empty, or non-function snippets."""
    if not code or len(code.strip()) < MIN_CODE_LENGTH:
        return False
    # Must contain at least one function-like construct
    if not re.search(
        r"(def |void |int |char |function |public |private |\bfn\b|static )",
        code,
        re.IGNORECASE,
    ):
        return False
    return True


def normalize_cwe(cwe_id: str) -> str:
    """Normalize CWE format — some datasets use CWE119 instead of CWE-119."""
    if not cwe_id:
        return "CWE-20"
    cwe_id = str(cwe_id).strip()
    if not cwe_id.startswith("CWE-"):
        cwe_id = re.sub(r"(?i)cwe(\d+)", r"CWE-\1", cwe_id)
    if not cwe_id.startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"
    return cwe_id


def cwe_to_finding(cwe_id: str, source: str = "") -> dict:
    cwe_id = normalize_cwe(cwe_id)
    meta   = CWE_META.get(cwe_id, ("Unknown Vulnerability", "potential security issue"))
    return {
        "category":      meta[0],
        "cwe_ids":       [cwe_id],
        "cwe_id":        cwe_id,
        "affected_code": meta[1],
        "source":        source,
    }


def deduplicate(examples: list) -> list:
    """Remove exact duplicate code snippets using MD5 hash of prompt prefix."""
    seen, result, removed = set(), [], 0
    for ex in examples:
        h = hashlib.md5(ex["instruction"][:300].encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            result.append(ex)
        else:
            removed += 1
    if removed:
        print(f"   🧹 Removed {removed} duplicate examples")
    return result


# ─── Training example builder ──────────────────────────────

def make_example(
    code:      str,
    finding:   dict,
    verdict:   str,
    reasoning: str,
) -> dict:
    """
    Formats one training example as an Alpaca-style prompt/completion pair
    matching the exact prompt format used in ValidationAgent.run().
    """
    prompt = f"""You are a senior security engineer performing validation review.

Code:
```
{code}
```

Finding to validate:
{json.dumps(finding, indent=2)}

Determine if this finding is:
- CONFIRMED: genuinely present and exploitable in this specific code
- FALSE_POSITIVE: pattern matched but not actually exploitable in context
- NEEDS_CONTEXT: might be vulnerable but requires more context to confirm

Respond with a JSON object:
{{"verdict": "CONFIRMED|FALSE_POSITIVE|NEEDS_CONTEXT", "reasoning": "one sentence"}}"""

    return {
        "instruction": prompt,
        "output":      json.dumps({"verdict": verdict, "reasoning": reasoning}),
        "source":      finding.get("source", "unknown"),
        "cwe_id":      finding.get("cwe_id", ""),
        "verdict":     verdict,
    }


# ─── LLM reasoning generator ───────────────────────────────

# Ollama occasionally fails to emit a stop token and generates until it is
# cut off; without a socket timeout that blocks the whole build forever.
# After this many consecutive failures we give up on the LLM entirely and
# use template reasoning for the rest of the run.
_LLM_STATE = {
    "client": None,
    "consecutive_failures": 0,
    "disabled": False,
    "calls": 0,
}
LLM_TIMEOUT_SECONDS   = 30
LLM_MAX_TOKENS        = 100
LLM_FAILURE_THRESHOLD = 5


def _fallback_reasoning(finding: dict, verdict: str) -> str:
    fallbacks = {
        "CONFIRMED": (
            f"{finding.get('affected_code', 'The pattern')} is directly "
            f"exploitable with external input"
        ),
        "FALSE_POSITIVE": (
            "Pattern present syntactically but not exploitable in this "
            "specific context"
        ),
        "NEEDS_CONTEXT": (
            "Cannot confirm exploitability without additional context about "
            "callers or runtime conditions"
        ),
    }
    return fallbacks.get(verdict, "")


def generate_reasoning(code: str, finding: dict, verdict: str) -> str:
    """
    Uses llama3.2 to generate a natural one-sentence reasoning string.
    Falls back to template strings if Ollama is slow or unavailable.
    """
    if _LLM_STATE["disabled"]:
        return _fallback_reasoning(finding, verdict)

    if _LLM_STATE["client"] is None:
        import ollama
        _LLM_STATE["client"] = ollama.Client(timeout=LLM_TIMEOUT_SECONDS)

    # Each call takes ~0.5-1s; without progress a long run looks frozen.
    _LLM_STATE["calls"] += 1
    if _LLM_STATE["calls"] % 25 == 0:
        print(f"      … {_LLM_STATE['calls']} reasoning strings generated",
              flush=True)

    try:
        response = _LLM_STATE["client"].chat(
            model=OLLAMA_LLM,
            messages=[{
                "role": "user",
                "content": (
                    f"Given this code and finding, write ONE concise sentence "
                    f"explaining why the verdict is {verdict}.\n\n"
                    f"Code:\n```\n{code[:500]}\n```\n\n"
                    f"Finding: {json.dumps(finding)}\n\n"
                    f"Write only the single reasoning sentence, nothing else."
                ),
            }],
            options={
                "temperature": 0.3,
                "num_predict": LLM_MAX_TOKENS,
            },
        )
        _LLM_STATE["consecutive_failures"] = 0
        return response["message"]["content"].strip()

    except Exception as e:
        _LLM_STATE["consecutive_failures"] += 1
        if _LLM_STATE["consecutive_failures"] >= LLM_FAILURE_THRESHOLD:
            _LLM_STATE["disabled"] = True
            print(
                f"\n⚠️  Ollama failed {LLM_FAILURE_THRESHOLD} times in a row "
                f"({type(e).__name__}) — falling back to template reasoning "
                f"for the rest of this run.\n"
            )
        return _fallback_reasoning(finding, verdict)


# ─── Manual examples ───────────────────────────────────────

def load_manual() -> list:
    """
    High-quality hand-crafted examples covering C/C++ and Python.
    Always included regardless of other dataset availability.
    """
    raw = [

        # ── CONFIRMED — C/C++ ──────────────────────────────
        (
            "void login(char *username) {\n"
            "    char buf[64];\n"
            "    strcpy(buf, username);\n"
            "    printf(\"Welcome %s\\n\", buf);\n"
            "}",
            {"category": "Buffer Overflow", "cwe_ids": ["CWE-120"],
             "cwe_id": "CWE-120", "affected_code": "strcpy(buf, username)",
             "source": "manual"},
            "CONFIRMED",
            "strcpy copies unsanitized external input into a fixed 64-byte stack "
            "buffer with no bounds check — directly exploitable",
        ),
        (
            "void process() {\n"
            "    char *data = (char *)malloc(256);\n"
            "    strcpy(data, \"sensitive\");\n"
            "    free(data);\n"
            "    printf(\"Data: %s\\n\", data);\n"
            "}",
            {"category": "Use After Free", "cwe_ids": ["CWE-416"],
             "cwe_id": "CWE-416", "affected_code": "printf after free(data)",
             "source": "manual"},
            "CONFIRMED",
            "data is dereferenced after free() with no reassignment — classic "
            "use-after-free, heap contents unpredictable",
        ),
        (
            "void cleanup(char *ptr) {\n"
            "    free(ptr);\n"
            "    if (error) {\n"
            "        free(ptr);\n"
            "    }\n"
            "}",
            {"category": "Double Free", "cwe_ids": ["CWE-415"],
             "cwe_id": "CWE-415", "affected_code": "free(ptr) called twice",
             "source": "manual"},
            "CONFIRMED",
            "ptr is freed unconditionally then freed again in the error branch — "
            "heap corruption on any error condition",
        ),
        (
            "void log_input(char *user_input) {\n"
            "    printf(user_input);\n"
            "}",
            {"category": "Format String", "cwe_ids": ["CWE-134"],
             "cwe_id": "CWE-134", "affected_code": "printf(user_input)",
             "source": "manual"},
            "CONFIRMED",
            "User-controlled string passed as printf format argument — attacker "
            "can read stack memory or execute arbitrary code with %n",
        ),
        (
            "void run_cmd(char *filename) {\n"
            "    char cmd[256];\n"
            "    sprintf(cmd, \"cat %s\", filename);\n"
            "    system(cmd);\n"
            "}",
            {"category": "Command Injection", "cwe_ids": ["CWE-78"],
             "cwe_id": "CWE-78", "affected_code": "system(cmd) with unsanitized filename",
             "source": "manual"},
            "CONFIRMED",
            "filename is unsanitized and injected into a shell command — attacker "
            "can append ; rm -rf / or similar",
        ),
        (
            "void allocate(unsigned int n) {\n"
            "    char *buf = malloc(n * sizeof(char));\n"
            "    memcpy(buf, src, n);\n"
            "}",
            {"category": "Integer Overflow", "cwe_ids": ["CWE-190", "CWE-122"],
             "cwe_id": "CWE-190", "affected_code": "malloc(n * sizeof(char))",
             "source": "manual"},
            "CONFIRMED",
            "Arithmetic on user-supplied n before malloc can wrap to zero on "
            "large values, allocating a tiny buffer then overflowing it with memcpy",
        ),

        # ── CONFIRMED — Python ─────────────────────────────
        (
            "def get_user(username):\n"
            "    query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchall()",
            {"category": "SQL Injection", "cwe_ids": ["CWE-89"],
             "cwe_id": "CWE-89", "affected_code": "string concatenation into SQL",
             "source": "manual"},
            "CONFIRMED",
            "Username concatenated directly into SQL string with no "
            "parameterization — trivially exploitable with ' OR '1'='1",
        ),
        (
            "import os\n"
            "def ping_host(host):\n"
            "    os.system(\"ping -c 4 \" + host)",
            {"category": "Command Injection", "cwe_ids": ["CWE-78"],
             "cwe_id": "CWE-78", "affected_code": "os.system with user-supplied host",
             "source": "manual"},
            "CONFIRMED",
            "host is user-supplied and concatenated into a shell command — "
            "attacker can append ; malicious_command",
        ),
        (
            "import pickle\n"
            "def load_session(data):\n"
            "    return pickle.loads(data)",
            {"category": "Insecure Deserialization", "cwe_ids": ["CWE-502"],
             "cwe_id": "CWE-502", "affected_code": "pickle.loads(data)",
             "source": "manual"},
            "CONFIRMED",
            "pickle.loads on untrusted data allows arbitrary code execution via "
            "crafted __reduce__ methods",
        ),
        (
            "from flask import request, send_file\n"
            "def download():\n"
            "    filename = request.args.get(\"file\")\n"
            "    return send_file(\"/var/www/files/\" + filename)",
            {"category": "Path Traversal", "cwe_ids": ["CWE-22"],
             "cwe_id": "CWE-22", "affected_code": "\"/var/www/files/\" + filename",
             "source": "manual"},
            "CONFIRMED",
            "User-controlled filename concatenated to path with no sanitization — "
            "allows ../../../etc/passwd traversal",
        ),
        (
            "def connect_db():\n"
            "    password = \"admin123\"\n"
            "    api_key = \"sk-abc123secretkey\"\n"
            "    conn = db.connect(user=\"admin\", password=password)\n"
            "    return conn",
            {"category": "Hardcoded Credentials", "cwe_ids": ["CWE-798"],
             "cwe_id": "CWE-798", "affected_code": "password = \"admin123\"",
             "source": "manual"},
            "CONFIRMED",
            "Plaintext credentials hardcoded in source — exposed in version "
            "control and any compiled binary",
        ),
        (
            "import hashlib\n"
            "def hash_password(password):\n"
            "    return hashlib.md5(password.encode()).hexdigest()",
            {"category": "Weak Cryptography", "cwe_ids": ["CWE-327"],
             "cwe_id": "CWE-327", "affected_code": "hashlib.md5(...)",
             "source": "manual"},
            "CONFIRMED",
            "MD5 is cryptographically broken — trivially reversible via rainbow "
            "tables, unsuitable for password hashing",
        ),
        (
            "import requests\n"
            "def fetch_data(url):\n"
            "    response = requests.get(url, verify=False)\n"
            "    return response.json()",
            {"category": "SSL Verification Disabled", "cwe_ids": ["CWE-295"],
             "cwe_id": "CWE-295", "affected_code": "verify=False",
             "source": "manual"},
            "CONFIRMED",
            "Disabling SSL certificate verification allows man-in-the-middle "
            "attacks on all HTTPS connections made by this function",
        ),
        (
            "import random\n"
            "def generate_token():\n"
            "    return str(random.random())",
            {"category": "Weak PRNG", "cwe_ids": ["CWE-338"],
             "cwe_id": "CWE-338", "affected_code": "random.random()",
             "source": "manual"},
            "CONFIRMED",
            "random.random() is not cryptographically secure — output is "
            "predictable from seed, unsuitable for security tokens",
        ),

        # ── FALSE POSITIVE — C/C++ ─────────────────────────
        (
            "void copy_greeting(void) {\n"
            "    char buf[64];\n"
            "    strcpy(buf, \"Hello, World!\");\n"
            "}",
            {"category": "Buffer Overflow", "cwe_ids": ["CWE-120"],
             "cwe_id": "CWE-120", "affected_code": "strcpy(buf, ...)",
             "source": "manual"},
            "FALSE_POSITIVE",
            "Source is a string literal of known fixed length (13 chars) that "
            "fits well within the 64-byte buffer — no external input involved",
        ),
        (
            "void increment(int *counter) {\n"
            "    pthread_mutex_lock(&mtx);\n"
            "    (*counter)++;\n"
            "    pthread_mutex_unlock(&mtx);\n"
            "}",
            {"category": "Race Condition", "cwe_ids": ["CWE-362"],
             "cwe_id": "CWE-362", "affected_code": "counter++ in thread",
             "source": "manual"},
            "FALSE_POSITIVE",
            "Counter modification is properly protected by mutex lock/unlock — "
            "race condition is prevented",
        ),
        (
            "void process_config(void) {\n"
            "    char buf[256];\n"
            "    strcpy(buf, DEFAULT_CONFIG_PATH);\n"
            "}",
            {"category": "Buffer Overflow", "cwe_ids": ["CWE-120"],
             "cwe_id": "CWE-120", "affected_code": "strcpy(buf, DEFAULT_CONFIG_PATH)",
             "source": "manual"},
            "FALSE_POSITIVE",
            "DEFAULT_CONFIG_PATH is a compile-time constant — no external input "
            "and its length is bounded at compile time",
        ),

        # ── FALSE POSITIVE — Python ────────────────────────
        (
            "def get_user(user_id: int):\n"
            "    query = \"SELECT * FROM users WHERE id = %s\"\n"
            "    cursor.execute(query, (user_id,))\n"
            "    return cursor.fetchone()",
            {"category": "SQL Injection", "cwe_ids": ["CWE-89"],
             "cwe_id": "CWE-89", "affected_code": "cursor.execute",
             "source": "manual"},
            "FALSE_POSITIVE",
            "Parameterized query with %s placeholder and separate parameter tuple "
            "correctly prevents SQL injection",
        ),
        (
            "import hashlib\n"
            "def get_file_hash(filepath: str) -> str:\n"
            "    with open(filepath, 'rb') as f:\n"
            "        return hashlib.md5(f.read()).hexdigest()",
            {"category": "Weak Cryptography", "cwe_ids": ["CWE-327"],
             "cwe_id": "CWE-327", "affected_code": "hashlib.md5(...)",
             "source": "manual"},
            "FALSE_POSITIVE",
            "MD5 used for file integrity checksumming not password hashing — "
            "acceptable non-security use of MD5",
        ),
        (
            "import random\n"
            "def pick_color() -> str:\n"
            "    colors = [\"red\", \"green\", \"blue\"]\n"
            "    return random.choice(colors)",
            {"category": "Weak PRNG", "cwe_ids": ["CWE-338"],
             "cwe_id": "CWE-338", "affected_code": "random.choice(...)",
             "source": "manual"},
            "FALSE_POSITIVE",
            "random.choice used for non-security UI color selection — "
            "cryptographic randomness is not required here",
        ),
        (
            "import xml.etree.ElementTree as ET\n"
            "def parse_config() -> ET.Element:\n"
            "    tree = ET.parse(\"config.xml\")\n"
            "    return tree.getroot()",
            {"category": "XXE", "cwe_ids": ["CWE-611"],
             "cwe_id": "CWE-611", "affected_code": "ET.parse(...)",
             "source": "manual"},
            "FALSE_POSITIVE",
            "Parsing a hardcoded local config file — no external or "
            "user-supplied XML input involved",
        ),
        (
            "def verify_token(token: str, expected: str) -> bool:\n"
            "    import hmac\n"
            "    return hmac.compare_digest(token, expected)",
            {"category": "Improper Authentication", "cwe_ids": ["CWE-287"],
             "cwe_id": "CWE-287", "affected_code": "token comparison",
             "source": "manual"},
            "FALSE_POSITIVE",
            "hmac.compare_digest performs constant-time comparison preventing "
            "timing attacks — this is the correct secure pattern",
        ),

        # ── NEEDS CONTEXT ──────────────────────────────────
        (
            "void copy_data(char *src, int validated) {\n"
            "    char buf[64];\n"
            "    if (validated) strcpy(buf, src);\n"
            "}",
            {"category": "Buffer Overflow", "cwe_ids": ["CWE-120"],
             "cwe_id": "CWE-120", "affected_code": "strcpy(buf, src)",
             "source": "manual"},
            "NEEDS_CONTEXT",
            "strcpy guarded by validated flag — exploitability depends on whether "
            "caller reliably enforces that src length fits in buf",
        ),
        (
            "def execute_query(query_str: str):\n"
            "    cursor.execute(query_str)",
            {"category": "SQL Injection", "cwe_ids": ["CWE-89"],
             "cwe_id": "CWE-89", "affected_code": "cursor.execute(query_str)",
             "source": "manual"},
            "NEEDS_CONTEXT",
            "Query string passed as parameter — cannot confirm SQL injection "
            "without examining all call sites that supply query_str",
        ),
        (
            "def load_data(serialized: bytes, trusted: bool):\n"
            "    import pickle\n"
            "    if trusted:\n"
            "        return pickle.loads(serialized)\n"
            "    return None",
            {"category": "Insecure Deserialization", "cwe_ids": ["CWE-502"],
             "cwe_id": "CWE-502", "affected_code": "pickle.loads(serialized)",
             "source": "manual"},
            "NEEDS_CONTEXT",
            "Deserialization guarded by trusted flag — depends on whether "
            "callers set trusted=True only for genuinely safe sources",
        ),
        (
            "def process_file(filename: str):\n"
            "    safe_name = sanitize(filename)\n"
            "    return open(\"/uploads/\" + safe_name).read()",
            {"category": "Path Traversal", "cwe_ids": ["CWE-22"],
             "cwe_id": "CWE-22", "affected_code": "\"/uploads/\" + safe_name",
             "source": "manual"},
            "NEEDS_CONTEXT",
            "Path constructed from sanitized filename — exploitability depends "
            "on whether sanitize() correctly blocks path traversal sequences",
        ),
    ]

    examples = [make_example(c, f, v, r) for c, f, v, r in raw]
    print(f"   ✅ Manual: {len(examples)} examples")
    return examples


# ─── PrimeVul ──────────────────────────────────────────────

def load_primevul(gen: bool) -> list:
    """
    PrimeVul JSON format:
    {
      "func":   "void foo(...) { ... }",
      "target": 1,
      "cve_id": "CVE-2021-...",
      "cwe_id": "CWE-120"
    }

    target=1 → CONFIRMED
    target=0 → FALSE_POSITIVE (same CWE, handled safely in this version)
    """
    path = DATA_DIR / "primevul" / "primevul_train.jsonl"
    if not path.exists():
        print(f"⚠️  PrimeVul not found at {path}, skipping")
        return []

    print("📂 Loading PrimeVul...")

    data = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data.append(json.loads(line))

    confirmed = [
        d for d in data
        if d.get("target") == 1
        and d.get("cwe")
        and is_valid_code(d.get("func", ""))
    ]
    not_vuln = [
        d for d in data
        if d.get("target") == 0
        and d.get("cwe")
        and is_valid_code(d.get("func", ""))
    ]

    random.shuffle(confirmed)
    random.shuffle(not_vuln)
    confirmed = confirmed[:SAMPLE_LIMITS["primevul_confirmed"]]
    not_vuln  = not_vuln[:SAMPLE_LIMITS["primevul_false_positive"]]

    examples = []

    for item in confirmed:
        code    = clean_code(item["func"])
        finding = cwe_to_finding(item["cwe"], "primevul")
        finding["commit_id"] = item.get("commit_id", "")
        reason  = (
            generate_reasoning(code, finding, "CONFIRMED")
            if gen
            else f"Vulnerable function confirmed by commit {item.get('commit_id', 'unknown')}"
        )
        examples.append(make_example(code, finding, "CONFIRMED", reason))

    for item in not_vuln:
        code    = clean_code(item["func"])
        finding = cwe_to_finding(item["cwe"], "primevul")
        reason  = (
            generate_reasoning(code, finding, "FALSE_POSITIVE")
            if gen
            else "Pattern present but properly handled — not exploitable in this version"
        )
        examples.append(make_example(code, finding, "FALSE_POSITIVE", reason))

    print(f"   ✅ PrimeVul: {len(examples)} examples "
          f"({len(confirmed)} confirmed, {len(not_vuln)} false positive)")
    return examples


# ─── BigVul ────────────────────────────────────────────────

def load_bigvul(gen: bool) -> list:
    """
    BigVul CSV columns include:
      func_before, func_after, target (1/0),
      CVE ID, CWE ID, Vulnerability Classification, Score

    target=1, func_before → CONFIRMED (vulnerable version before patch)
    """
    path = DATA_DIR / "bigvul" / "processed_data.csv"
    if not path.exists():
        print(f"⚠️  BigVul not found at {path}, skipping")
        return []

    print("📂 Loading BigVul...")

    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            if (
                row.get("target") == "1"
                and row.get("CWE ID")
                and is_valid_code(row.get("func_before", ""))
            ):
                rows.append(row)

    random.shuffle(rows)
    rows = rows[:SAMPLE_LIMITS["bigvul_confirmed"]]

    examples = []
    for row in rows:
        code    = clean_code(row.get("func_before", ""))
        cwe_id  = row.get("CWE ID", "CWE-20").strip()
        finding = cwe_to_finding(cwe_id, "bigvul")
        finding["cve_id"]     = row.get("CVE ID", "").strip()
        finding["cvss"]       = row.get("Score", "")
        finding["vuln_type"]  = row.get("Vulnerability Classification", "")

        reason = (
            generate_reasoning(code, finding, "CONFIRMED")
            if gen
            else f"Pre-patch function confirmed by {finding['cve_id']}"
        )
        examples.append(make_example(code, finding, "CONFIRMED", reason))

    print(f"   ✅ BigVul: {len(examples)} examples")
    return examples


# ─── Juliet ────────────────────────────────────────────────

def _extract_c_functions(text: str, name_regex: str) -> list:
    """
    Extract full bodies of C/C++ functions whose name matches name_regex,
    by finding the signature then brace-matching to the closing '}'.
    """
    funcs   = []
    pattern = re.compile(
        rf"^[ \t]*[\w \*]*?\b({name_regex})\s*\([^;{{]*\)\s*\n\{{",
        re.MULTILINE,
    )
    for m in pattern.finditer(text):
        brace_start = text.index("{", m.end() - 1)
        depth = 0
        i     = brace_start
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        else:
            continue
        funcs.append(text[m.start():i].strip())
    return funcs


def load_juliet(gen: bool) -> list:
    """
    Juliet folder structure:
      testcases/CWE119_.../CWE119_....c

    Unlike PrimeVul/BigVul, Juliet does NOT split vulnerable and safe
    code into separate files — each source file contains both a
    `..._bad()` function (vulnerable) and one or more `good*()`
    functions (safe variants of the same pattern) side by side.
    """
    juliet_dir = DATA_DIR / "juliet"
    if not juliet_dir.exists():
        print(f"⚠️  Juliet not found at {juliet_dir}, skipping")
        return []

    print("📂 Loading Juliet Test Suite...")

    src_files = (
        list(juliet_dir.rglob("*.c"))
        + list(juliet_dir.rglob("*.cpp"))
        + list(juliet_dir.rglob("*.java"))
    )
    random.shuffle(src_files)

    def cwe_from_path(p: Path) -> str:
        m = re.search(r"CWE(\d+)", str(p))
        return f"CWE-{m.group(1)}" if m else "CWE-20"

    bad_target  = SAMPLE_LIMITS["juliet_confirmed"]
    good_target = SAMPLE_LIMITS["juliet_false_positive"]
    examples    = []
    bad_count   = 0
    good_count  = 0

    for fpath in src_files:
        if bad_count >= bad_target and good_count >= good_target:
            break
        try:
            text = fpath.read_text(errors="replace")
        except Exception:
            continue

        cwe = cwe_from_path(fpath)

        if bad_count < bad_target:
            for func in _extract_c_functions(text, r"\w*_bad"):
                code = clean_code(func)
                if not is_valid_code(code):
                    continue
                finding = cwe_to_finding(cwe, "juliet")
                reason  = (
                    generate_reasoning(code, finding, "CONFIRMED")
                    if gen
                    else "Juliet intentionally vulnerable test case — bad pattern present"
                )
                examples.append(make_example(code, finding, "CONFIRMED", reason))
                bad_count += 1
                if bad_count >= bad_target:
                    break

        if good_count < good_target:
            for func in _extract_c_functions(text, r"\w*[Gg]ood\w*"):
                code = clean_code(func)
                if not is_valid_code(code):
                    continue
                finding = cwe_to_finding(cwe, "juliet")
                reason  = (
                    generate_reasoning(code, finding, "FALSE_POSITIVE")
                    if gen
                    else "Juliet safe test case — vulnerability pattern correctly mitigated"
                )
                examples.append(make_example(code, finding, "FALSE_POSITIVE", reason))
                good_count += 1
                if good_count >= good_target:
                    break

    print(f"   ✅ Juliet: {len(examples)} examples")
    return examples


# ─── Devign ────────────────────────────────────────────────

def load_devign(gen: bool) -> list:
    """
    Devign JSON format:
    {
      "func":    "...",
      "target":  0 or 1,
      "project": "linux|ffmpeg|qemu|wireshark"
    }

    Non-vulnerable real-world kernel/system code is used for
    NEEDS_CONTEXT because it is complex enough that more calling
    context is genuinely required to confirm exploitability.
    """
    devign_dir = DATA_DIR / "devign"
    func_path  = next(
        (devign_dir / n for n in ("function.json", "devign.json")
         if (devign_dir / n).exists()),
        None,
    )
    if func_path is None:
        print(
            f"⚠️  Devign function data not found — expected "
            f"{devign_dir / 'function.json'} (the CodeXGLUE defect-detection "
            f"file with idx/func/target/project). The *.txt files here are "
            f"split-index lists only. Skipping Devign."
        )
        return []

    print("📂 Loading Devign...")

    with open(func_path, encoding="utf-8") as f:
        data = json.load(f)

    # train.txt holds the row indices belonging to the train split; restrict to
    # them so the fine-tune set never sees Devign's held-out rows.
    index_path = devign_dir / "train.txt"
    if index_path.exists():
        with open(index_path, encoding="utf-8") as f:
            keep = {line.strip() for line in f if line.strip()}
        by_idx = {str(d.get("idx", i)): d for i, d in enumerate(data)}
        selected = [by_idx[k] for k in keep if k in by_idx]
        if selected:
            data = selected
        else:
            print("   ⚠️  train.txt indices matched no rows — using full file")

    not_vuln = [
        d for d in data
        if d.get("target") == 0
        and is_valid_code(d.get("func", ""))
    ]

    random.shuffle(not_vuln)
    not_vuln = not_vuln[:SAMPLE_LIMITS["devign_needs_context"]]

    kernel_cwes = ["CWE-362", "CWE-119", "CWE-476", "CWE-190", "CWE-416"]
    examples    = []

    for item in not_vuln:
        code    = clean_code(item["func"])
        cwe_id  = random.choice(kernel_cwes)
        finding = cwe_to_finding(cwe_id, "devign")
        finding["project"] = item.get("project", "unknown")

        reason = (
            generate_reasoning(code, finding, "NEEDS_CONTEXT")
            if gen
            else (
                f"Complex {item.get('project', 'system')} code — exploitability "
                f"depends on calling context and runtime conditions not visible here"
            )
        )
        examples.append(make_example(code, finding, "NEEDS_CONTEXT", reason))

    print(f"   ✅ Devign: {len(examples)} examples")
    return examples


# ─── SecurityEval ──────────────────────────────────────────

def load_security_eval(gen: bool) -> list:
    """
    SecurityEval JSON format:
    {
      "id":          "...",
      "description": "...",
      "code":        "def foo(): ...",
      "vulnerable":  true/false,
      "cwe":         "CWE-89",
      "language":    "Python"
    }

    Download: https://github.com/microsoft/SecurityEval
    Place at: data/securityeval/dataset.json
    """
    path = DATA_DIR / "securityeval" / "dataset.json"
    if not path.exists():
        print(f"⚠️  SecurityEval not found at {path}, skipping")
        return []

    print("📂 Loading SecurityEval...")

    with open(path) as f:
        data = json.load(f)

    # Filter Python samples (language field may be absent)
    python_data = [
        d for d in data
        if d.get("language", "Python").lower() in ("python", "")
        and is_valid_code(d.get("code", ""))
    ]

    if SAMPLE_LIMITS["securityeval"] is not None:
        python_data = python_data[:SAMPLE_LIMITS["securityeval"]]

    examples = []
    confirmed_count = 0
    fp_count        = 0

    for item in python_data:
        code    = clean_code(item.get("code", ""))
        cwe_id  = item.get("cwe", "CWE-20")
        verdict = "CONFIRMED" if item.get("vulnerable") else "FALSE_POSITIVE"
        finding = cwe_to_finding(cwe_id, "securityeval")
        finding["description"] = item.get("description", "")

        reason = (
            generate_reasoning(code, finding, verdict)
            if gen
            else f"SecurityEval Python sample labelled {verdict.lower()}"
        )
        examples.append(make_example(code, finding, verdict, reason))

        if verdict == "CONFIRMED":
            confirmed_count += 1
        else:
            fp_count += 1

    print(f"   ✅ SecurityEval: {len(examples)} examples "
          f"({confirmed_count} confirmed, {fp_count} false positive)")
    return examples


# ─── CVEFixes ──────────────────────────────────────────────

def load_cvefixes(gen: bool) -> list:
    """
    CVEFixes SQLite schema (relevant tables):
      file_change → code_before_change, code_after_change,
                    programming_language
      cve_commits → cve_id, hash
      cve         → cve_id, cwe_id, cvss_score

    Strategy:
      code_before_change + CVE confirmed → CONFIRMED
      code_after_change  (patch applied) → FALSE_POSITIVE
        The fixed code has the same CWE category but is now safe —
        ideal for teaching what a correctly patched version looks like.

    Download: https://github.com/secureIT-project/CVEFixes/releases
    Place at: data/cvefixes/CVEfixes.db
    """
    import sqlite3

    path = DATA_DIR / "cvefixes" / "CVEfixes_v1.0.8.sql"
    if not path.exists():
        print(f"⚠️  CVEFixes not found at {path}, skipping")
        return []

    # The project stores a SQL dump file, not a SQLite database file.
    # Opening that directly triggers sqlite3.DatabaseError and aborts the build.
    if path.suffix.lower() != ".db":
        print(
            f"⚠️  CVEFixes data at {path} is not a SQLite database file "
            f"(.db); skipping because the script requires a real DB."
        )
        return []

    print("📂 Loading CVEFixes (Python)...")

    try:
        conn = sqlite3.connect(path)
    except Exception as e:
        print(
            f"⚠️  CVEFixes database could not be opened at {path} "
            f"({type(e).__name__}: {e}). Skipping."
        )
        return []

    conn.row_factory = sqlite3.Row
    cur  = conn.cursor()

    cur.execute("""
        SELECT
            fc.code_before_change,
            fc.code_after_change,
            cv.cve_id,
            cv.cwe_id,
            cv.cvss_score
        FROM file_change fc
        JOIN cve_commits cc ON fc.hash     = cc.hash
        JOIN cve         cv ON cc.cve_id   = cv.cve_id
        WHERE fc.programming_language      = 'Python'
          AND fc.code_before_change IS NOT NULL
          AND fc.code_after_change  IS NOT NULL
          AND cv.cwe_id             IS NOT NULL
          AND LENGTH(fc.code_before_change) BETWEEN 30 AND 3000
          AND LENGTH(fc.code_after_change)  BETWEEN 30 AND 3000
        LIMIT 1000
    """)

    rows = list(cur.fetchall())
    conn.close()
    random.shuffle(rows)

    limit_c  = SAMPLE_LIMITS["cvefixes_confirmed"]
    limit_fp = SAMPLE_LIMITS["cvefixes_false_positive"]
    confirmed_rows = rows[:limit_c]
    safe_rows      = rows[limit_c:limit_c + limit_fp]

    examples = []

    # Before patch → CONFIRMED
    for row in confirmed_rows:
        code = clean_code(row["code_before_change"])
        if not is_valid_code(code):
            continue
        finding = cwe_to_finding(row["cwe_id"] or "CWE-20", "cvefixes")
        finding["cve_id"] = row["cve_id"] or ""
        finding["cvss"]   = row["cvss_score"]

        reason = (
            generate_reasoning(code, finding, "CONFIRMED")
            if gen
            else f"Pre-patch Python code from {row['cve_id']} — confirmed vulnerable"
        )
        examples.append(make_example(code, finding, "CONFIRMED", reason))

    # After patch → FALSE_POSITIVE
    for row in safe_rows:
        code = clean_code(row["code_after_change"])
        if not is_valid_code(code):
            continue
        finding = cwe_to_finding(row["cwe_id"] or "CWE-20", "cvefixes")
        finding["cve_id"] = row["cve_id"] or ""

        reason = (
            generate_reasoning(code, finding, "FALSE_POSITIVE")
            if gen
            else f"Post-patch Python code from {row['cve_id']} — vulnerability fixed"
        )
        examples.append(make_example(code, finding, "FALSE_POSITIVE", reason))

    print(f"   ✅ CVEFixes: {len(examples)} Python examples")
    return examples


# ─── Train / val / test split ──────────────────────────────

def split_dataset(examples: list) -> dict:
    """
    Stratified 80 / 10 / 10 split by verdict to keep class balance
    in every split.
    """
    by_verdict = {"CONFIRMED": [], "FALSE_POSITIVE": [], "NEEDS_CONTEXT": []}
    for ex in examples:
        by_verdict[ex["verdict"]].append(ex)

    train, val, test = [], [], []

    for verdict, items in by_verdict.items():
        random.shuffle(items)
        n       = len(items)
        n_val   = max(1, int(n * 0.1))
        n_test  = max(1, int(n * 0.1))
        n_train = n - n_val - n_test

        train += items[:n_train]
        val   += items[n_train:n_train + n_val]
        test  += items[n_train + n_val:]

    random.shuffle(train)
    random.shuffle(val)
    random.shuffle(test)

    return {"train": train, "validation": val, "test": test}


# ─── Stats ─────────────────────────────────────────────────

def print_stats(examples: list, label: str = "Dataset"):
    counts  = Counter(ex["verdict"] for ex in examples)
    sources = Counter(ex["source"]  for ex in examples)
    cwes    = Counter(ex["cwe_id"]  for ex in examples)
    total   = len(examples)

    print(f"\n{'═'*55}")
    print(f"  {label}")
    print(f"{'─'*55}")
    print(f"  Total:           {total}")
    print(f"  CONFIRMED:       {counts.get('CONFIRMED', 0)}")
    print(f"  FALSE_POSITIVE:  {counts.get('FALSE_POSITIVE', 0)}")
    print(f"  NEEDS_CONTEXT:   {counts.get('NEEDS_CONTEXT', 0)}")

    print(f"\n  By source:")
    for src, cnt in sources.most_common():
        pct = cnt / total * 100
        print(f"    {src:20} {cnt:4}  ({pct:.1f}%)")

    print(f"\n  Top CWEs:")
    for cwe, cnt in cwes.most_common(10):
        print(f"    {cwe:12} {cnt}")

    # Class imbalance warnings
    for label_v, count in counts.items():
        pct = count / total * 100 if total > 0 else 0
        if pct < 15:
            print(f"\n  ⚠️  {label_v} only {pct:.1f}% — add more examples")

    print(f"{'═'*55}\n")


# ─── Main ──────────────────────────────────────────────────

def build_dataset(
    gen_reasons:  bool = True,
    verify_only:  bool = False,
    stats_only:   bool = False,
    output_path:  str  = OUTPUT_FILE,
    splits_path:  str  = SPLIT_FILE,
):
    # Verify only — check which datasets are present
    if verify_only:
        print("🔍 Checking dataset availability...\n")
        checks = [
            ("PrimeVul",     DATA_DIR / "primevul" / "primevul_train.jsonl"),
            ("BigVul",       DATA_DIR / "bigvul"   / "processed_data.csv"),
            ("Juliet",       DATA_DIR / "juliet"),
            ("Devign",       DATA_DIR / "devign"   / "function.json"),
            ("CVEFixes",     DATA_DIR / "cvefixes" / "CVEfixes_v1.0.8.sql"),
        ]
        for name, p in checks:
            exists = p.exists()
            size   = (
                f"{p.stat().st_size / 1e6:.1f} MB"
                if exists and p.is_file()
                else "directory" if exists
                else ""
            )
            print(f"  {'✅' if exists else '❌'} {name:15} {str(p):50} {size}")
        return

    # Stats only — show stats on existing dataset
    if stats_only:
        if not Path(output_path).exists():
            print(f"❌ {output_path} not found — run build first")
            return
        with open(output_path) as f:
            data = json.load(f)
        print_stats(data, f"Existing dataset: {output_path}")
        return

    # Full build
    print("🔨 Building Validation Agent finetuning dataset...\n")

    all_examples = []
    all_examples += load_manual()
    all_examples += load_primevul(gen_reasons)
    all_examples += load_bigvul(gen_reasons)
    all_examples += load_juliet(gen_reasons)
    all_examples += load_devign(gen_reasons)
    all_examples += load_security_eval(gen_reasons)
    all_examples += load_cvefixes(gen_reasons)

    # Deduplicate
    all_examples = deduplicate(all_examples)

    # Stats
    print_stats(all_examples, "Full Dataset")

    # Split
    splits = split_dataset(all_examples)
    print(f"  Split sizes:")
    print(f"    Train:      {len(splits['train'])}")
    print(f"    Validation: {len(splits['validation'])}")
    print(f"    Test:       {len(splits['test'])}\n")

    # Save
    with open(output_path, "w") as f:
        json.dump(all_examples, f, indent=2)

    with open(splits_path, "w") as f:
        json.dump(splits, f, indent=2)

    print(f"✅ Saved full dataset  → {output_path}")
    print(f"✅ Saved split dataset → {splits_path}")
    print(f"\nTotal examples: {len(all_examples)}")


# ─── Entry point ───────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build Validation Agent finetuning dataset"
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM reasoning generation (faster, lower quality reasoning strings)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only check which dataset files are present",
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="Show stats on existing dataset without rebuilding",
    )
    parser.add_argument(
        "--output",
        default=OUTPUT_FILE,
        help=f"Output file path (default: {OUTPUT_FILE})",
    )
    parser.add_argument(
        "--splits",
        default=SPLIT_FILE,
        help=f"Splits file path (default: {SPLIT_FILE})",
    )
    args = parser.parse_args()

    build_dataset(
        gen_reasons = not args.no_llm,
        verify_only = args.verify_only,
        stats_only  = args.stats_only,
        output_path = args.output,
        splits_path = args.splits,
    )