# finetune/preprocess.py
"""
Preprocesses all datasets into clean training examples
for the Validation Agent finetuning task.

Run:
    python preprocess.py                # full pipeline
    python preprocess.py --no-llm      # skip LLM reasoning generation
    python preprocess.py --verify-only # just check dataset stats
"""

import json
import csv
import re
import random
import hashlib
import argparse
from pathlib import Path
from collections import Counter

# ─── Config ────────────────────────────────────────────────
DATA_DIR        = Path("data")
OUTPUT_FILE     = "validation_agent_dataset.json"
SPLIT_FILE      = "dataset_splits.json"
RANDOM_SEED     = 42
MAX_CODE_LENGTH = 1200    # truncate longer functions
MIN_CODE_LENGTH = 30      # skip trivially short snippets
OLLAMA_LLM      = "llama3.2"

SAMPLE_LIMITS = {
    "primevul_confirmed":       300,
    "primevul_false_positive":  200,
    "bigvul_confirmed":         300,
    "juliet_confirmed":         200,
    "juliet_false_positive":    300,
    "devign_needs_context":     200,
    "securityeval":             None,   # include all
    "cvefixes_confirmed":       200,
    "cvefixes_false_positive":  200,
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
    "CWE-20":  ("Improper Input Validation", "missing input validation"),
}


# ─── Helpers ───────────────────────────────────────────────
def clean_code(code: str) -> str:
    """Normalize and truncate code."""
    if not code:
        return ""
    # Remove null bytes and normalize whitespace
    code = code.replace("\x00", "").strip()
    # Truncate
    if len(code) > MAX_CODE_LENGTH:
        code = code[:MAX_CODE_LENGTH] + "\n// ... (truncated)"
    return code


def is_valid_code(code: str) -> bool:
    """Filter out trivially short or empty snippets."""
    if not code or len(code.strip()) < MIN_CODE_LENGTH:
        return False
    # Must contain at least one function-like structure
    if not re.search(
        r"(def |void |int |char |function |public |private |\bfn\b)",
        code, re.IGNORECASE
    ):
        return False
    return True


def cwe_to_finding(cwe_id: str, source: str = "") -> dict:
    # Normalize CWE format — some datasets use "CWE119" not "CWE-119"
    if cwe_id and not cwe_id.startswith("CWE-"):
        cwe_id = re.sub(r"CWE(\d+)", r"CWE-\1", cwe_id)
    meta = CWE_META.get(cwe_id, ("Unknown Vulnerability", "potential security issue"))
    return {
        "category":      meta[0],
        "cwe_ids":       [cwe_id],
        "cwe_id":        cwe_id,
        "affected_code": meta[1],
        "source":        source,
    }


def deduplicate(examples: list) -> list:
    """Remove exact duplicate code snippets."""
    seen    = set()
    result  = []
    removed = 0
    for ex in examples:
        # Hash the code to detect duplicates
        code_hash = hashlib.md5(
            ex["instruction"][:200].encode()
        ).hexdigest()
        if code_hash not in seen:
            seen.add(code_hash)
            result.append(ex)
        else:
            removed += 1
    if removed:
        print(f"   🧹 Removed {removed} duplicate examples")
    return result


def make_example(
    code: str,
    finding: dict,
    verdict: str,
    reasoning: str,
) -> dict:
    prompt = f"""You are a senior security engineer performing validation review.

Code:
{code}

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


def generate_reasoning(code: str, finding: dict, verdict: str) -> str:
    """Use LLM to generate natural reasoning string."""
    import ollama
    try:
        response = ollama.chat(
            model=OLLAMA_LLM,
            messages=[{
                "role": "user",
                "content": (
                    f"Given this code and finding, write ONE sentence "
                    f"explaining why the verdict is {verdict}.\n\n"
                    f"Code:\n{code[:400]}\n\n"
                    f"Finding: {json.dumps(finding)}\n\n"
                    f"Write only the reasoning sentence."
                )
            }],
            options={"temperature": 0.3},
        )
        return response["message"]["content"].strip()
    except Exception:
        fallbacks = {
            "CONFIRMED":      f"{finding.get('affected_code', 'Pattern')} is directly exploitable",
            "FALSE_POSITIVE": "Pattern present but not exploitable in this context",
            "NEEDS_CONTEXT":  "Cannot confirm without additional calling context",
        }
        return fallbacks.get(verdict, "")


# ─── Dataset loaders ───────────────────────────────────────

def load_primevul(gen: bool) -> list:
    path = DATA_DIR / "primevul" / "primevul_train.json"
    if not path.exists():
        print(f"⚠️  PrimeVul not found, skipping")
        return []
    print("📂 Loading PrimeVul...")

    with open(path) as f:
        data = json.load(f)

    confirmed = [d for d in data
                 if d.get("target") == 1
                 and d.get("cwe_id")
                 and is_valid_code(d.get("func", ""))]

    not_vuln  = [d for d in data
                 if d.get("target") == 0
                 and d.get("cwe_id")
                 and is_valid_code(d.get("func", ""))]

    random.shuffle(confirmed)
    random.shuffle(not_vuln)
    confirmed = confirmed[:SAMPLE_LIMITS["primevul_confirmed"]]
    not_vuln  = not_vuln[:SAMPLE_LIMITS["primevul_false_positive"]]

    examples = []
    for item in confirmed:
        code    = clean_code(item["func"])
        finding = cwe_to_finding(item["cwe_id"], "primevul")
        finding["cve_id"] = item.get("cve_id", "")
        reason  = generate_reasoning(code, finding, "CONFIRMED") if gen \
                  else f"Confirmed by {item.get('cve_id','CVE analysis')}"
        examples.append(make_example(code, finding, "CONFIRMED", reason))

    for item in not_vuln:
        code    = clean_code(item["func"])
        finding = cwe_to_finding(item["cwe_id"], "primevul")
        reason  = generate_reasoning(code, finding, "FALSE_POSITIVE") if gen \
                  else "Pattern present but properly handled in this version"
        examples.append(make_example(code, finding, "FALSE_POSITIVE", reason))

    print(f"   ✅ {len(examples)} examples")
    return examples


def load_bigvul(gen: bool) -> list:
    path = DATA_DIR / "bigvul" / "bigvul.csv"
    if not path.exists():
        print(f"⚠️  BigVul not found, skipping")
        return []
    print("📂 Loading BigVul...")

    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            if (row.get("vul") == "1"
                    and row.get("CWE ID")
                    and is_valid_code(row.get("func_before", ""))):
                rows.append(row)

    random.shuffle(rows)
    rows = rows[:SAMPLE_LIMITS["bigvul_confirmed"]]

    examples = []
    for row in rows:
        code    = clean_code(row.get("func_before", ""))
        cwe_id  = row.get("CWE ID", "CWE-20").strip()
        finding = cwe_to_finding(cwe_id, "bigvul")
        finding["cve_id"]    = row.get("CVE ID", "").strip()
        finding["vuln_type"] = row.get("vulnerability_type", "")
        reason  = generate_reasoning(code, finding, "CONFIRMED") if gen \
                  else f"Pre-patch function confirmed vulnerable by {finding['cve_id']}"
        examples.append(make_example(code, finding, "CONFIRMED", reason))

    print(f"   ✅ {len(examples)} examples")
    return examples


def load_juliet(gen: bool) -> list:
    juliet_dir = DATA_DIR / "juliet"
    if not juliet_dir.exists():
        print(f"⚠️  Juliet not found, skipping")
        return []
    print("📂 Loading Juliet...")

    bad_files  = list(juliet_dir.rglob("*_bad*.c")) + \
                 list(juliet_dir.rglob("*_bad*.java"))
    good_files = list(juliet_dir.rglob("*_good*.c")) + \
                 list(juliet_dir.rglob("*_good*.java"))

    random.shuffle(bad_files)
    random.shuffle(good_files)
    bad_files  = bad_files[:SAMPLE_LIMITS["juliet_confirmed"]]
    good_files = good_files[:SAMPLE_LIMITS["juliet_false_positive"]]

    def cwe_from_path(p):
        m = re.search(r"CWE(\d+)", str(p))
        return f"CWE-{m.group(1)}" if m else "CWE-20"

    examples = []
    for fpath in bad_files:
        try:
            code = clean_code(fpath.read_text(errors="replace"))
            if not is_valid_code(code):
                continue
            finding = cwe_to_finding(cwe_from_path(fpath), "juliet")
            reason  = generate_reasoning(code, finding, "CONFIRMED") if gen \
                      else "Juliet intentionally vulnerable test case"
            examples.append(make_example(code, finding, "CONFIRMED", reason))
        except Exception:
            pass

    for fpath in good_files:
        try:
            code = clean_code(fpath.read_text(errors="replace"))
            if not is_valid_code(code):
                continue
            finding = cwe_to_finding(cwe_from_path(fpath), "juliet")
            reason  = generate_reasoning(code, finding, "FALSE_POSITIVE") if gen \
                      else "Juliet safe version — pattern handled correctly"
            examples.append(make_example(code, finding, "FALSE_POSITIVE", reason))
        except Exception:
            pass

    print(f"   ✅ {len(examples)} examples")
    return examples


def load_devign(gen: bool) -> list:
    path = DATA_DIR / "devign" / "devign.json"
    if not path.exists():
        print(f"⚠️  Devign not found, skipping")
        return []
    print("📂 Loading Devign...")

    with open(path) as f:
        data = json.load(f)

    not_vuln = [d for d in data
                if d.get("target") == 0
                and is_valid_code(d.get("func", ""))]

    random.shuffle(not_vuln)
    not_vuln = not_vuln[:SAMPLE_LIMITS["devign_needs_context"]]

    kernel_cwes = ["CWE-362", "CWE-119", "CWE-476", "CWE-190", "CWE-416"]
    examples = []

    for item in not_vuln:
        code    = clean_code(item["func"])
        cwe_id  = random.choice(kernel_cwes)
        finding = cwe_to_finding(cwe_id, "devign")
        finding["project"] = item.get("project", "")
        reason  = generate_reasoning(code, finding, "NEEDS_CONTEXT") if gen \
                  else (f"Complex {item.get('project','system')} code — "
                        f"exploitability depends on calling context")
        examples.append(make_example(code, finding, "NEEDS_CONTEXT", reason))

    print(f"   ✅ {len(examples)} examples")
    return examples


def load_security_eval(gen: bool) -> list:
    path = DATA_DIR / "securityeval" / "dataset.json"
    if not path.exists():
        print(f"⚠️  SecurityEval not found, skipping")
        return []
    print("📂 Loading SecurityEval...")

    with open(path) as f:
        data = json.load(f)

    # Filter Python
    python_data = [d for d in data
                   if d.get("language", "").lower() in ("python", "")
                   and is_valid_code(d.get("code", ""))]

    examples = []
    for item in python_data:
        code    = clean_code(item.get("code", ""))
        cwe_id  = item.get("cwe", "CWE-20")
        verdict = "CONFIRMED" if item.get("vulnerable") else "FALSE_POSITIVE"
        finding = cwe_to_finding(cwe_id, "securityeval")
        finding["description"] = item.get("description", "")
        reason  = generate_reasoning(code, finding, verdict) if gen \
                  else f"SecurityEval Python sample — {verdict.lower()}"
        examples.append(make_example(code, finding, verdict, reason))

    print(f"   ✅ {len(examples)} examples")
    return examples


def load_cvefixes(gen: bool) -> list:
    import sqlite3

    path = DATA_DIR / "cvefixes" / "CVEfixes.db"
    if not path.exists():
        print(f"⚠️  CVEFixes not found, skipping")
        return []
    print("📂 Loading CVEFixes (Python)...")

    conn = sqlite3.connect(path)
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
        JOIN cve_commits cc ON fc.hash = cc.hash
        JOIN cve cv         ON cc.cve_id = cv.cve_id
        WHERE fc.programming_language = 'Python'
          AND fc.code_before_change IS NOT NULL
          AND fc.code_after_change  IS NOT NULL
          AND cv.cwe_id IS NOT NULL
          AND LENGTH(fc.code_before_change) BETWEEN 30 AND 3000
        LIMIT 1000
    """)

    rows = list(cur.fetchall())
    conn.close()
    random.shuffle(rows)

    confirmed_rows = rows[:SAMPLE_LIMITS["cvefixes_confirmed"]]
    safe_rows      = rows[SAMPLE_LIMITS["cvefixes_confirmed"]:
                          SAMPLE_LIMITS["cvefixes_confirmed"] +
                          SAMPLE_LIMITS["cvefixes_false_positive"]]

    examples = []

    for row in confirmed_rows:
        code = clean_code(row["code_before_change"])
        if not is_valid_code(code):
            continue
        finding = cwe_to_finding(row["cwe_id"] or "CWE-20", "cvefixes")
        finding["cve_id"] = row["cve_id"] or ""
        reason  = generate_reasoning(code, finding, "CONFIRMED") if gen \
                  else f"Pre-patch Python code from {row['cve_id']} — confirmed vulnerable"
        examples.append(make_example(code, finding, "CONFIRMED", reason))

    for row in safe_rows:
        code = clean_code(row["code_after_change"])
        if not is_valid_code(code):
            continue
        finding = cwe_to_finding(row["cwe_id"] or "CWE-20", "cvefixes")
        finding["cve_id"] = row["cve_id"] or ""
        reason  = generate_reasoning(code, finding, "FALSE_POSITIVE") if gen \
                  else f"Post-patch Python code from {row['cve_id']} — vulnerability fixed"
        examples.append(make_example(code, finding, "FALSE_POSITIVE", reason))

    print(f"   ✅ {len(examples)} examples")
    return examples


def load_manual() -> list:
    """High quality hand-crafted examples — always included."""
    raw = [
        # ── CONFIRMED ──────────────────────────────────────
        (
            "void login(char *username) {\n    char buf[64];\n    strcpy(buf, username);\n}",
            {"category": "Buffer Overflow", "cwe_ids": ["CWE-120"], "cwe_id": "CWE-120",
             "affected_code": "strcpy(buf, username)", "source": "manual"},
            "CONFIRMED",
            "strcpy copies unsanitized external input into fixed 64-byte stack buffer with no bounds check"
        ),
        (
            "def get_user(username):\n    query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n    cursor.execute(query)",
            {"category": "SQL Injection", "cwe_ids": ["CWE-89"], "cwe_id": "CWE-89",
             "affected_code": "string concatenation into SQL", "source": "manual"},
            "CONFIRMED",
            "Username concatenated directly into SQL string with no parameterization"
        ),
        (
            "import pickle\ndef load_session(data):\n    return pickle.loads(data)",
            {"category": "Insecure Deserialization", "cwe_ids": ["CWE-502"], "cwe_id": "CWE-502",
             "affected_code": "pickle.loads(data)", "source": "manual"},
            "CONFIRMED",
            "pickle.loads on untrusted data allows arbitrary code execution"
        ),
        (
            "void process() {\n    char *p = malloc(64);\n    free(p);\n    printf(\"%s\", p);\n}",
            {"category": "Use After Free", "cwe_ids": ["CWE-416"], "cwe_id": "CWE-416",
             "affected_code": "printf after free(p)", "source": "manual"},
            "CONFIRMED",
            "Pointer dereferenced after free with no reassignment"
        ),
        (
            "import requests\ndef fetch(url):\n    return requests.get(url, verify=False)",
            {"category": "SSL Verification Disabled", "cwe_ids": ["CWE-295"], "cwe_id": "CWE-295",
             "affected_code": "verify=False", "source": "manual"},
            "CONFIRMED",
            "Disabling SSL verification allows man-in-the-middle attacks"
        ),
        # ── FALSE POSITIVE ─────────────────────────────────
        (
            "void copy_greeting(void) {\n    char buf[64];\n    strcpy(buf, \"Hello!\");\n}",
            {"category": "Buffer Overflow", "cwe_ids": ["CWE-120"], "cwe_id": "CWE-120",
             "affected_code": "strcpy(buf, ...)", "source": "manual"},
            "FALSE_POSITIVE",
            "Source is a string literal of known length that fits in the 64-byte buffer"
        ),
        (
            "def get_user(user_id):\n    query = \"SELECT * FROM users WHERE id = %s\"\n    cursor.execute(query, (user_id,))",
            {"category": "SQL Injection", "cwe_ids": ["CWE-89"], "cwe_id": "CWE-89",
             "affected_code": "cursor.execute", "source": "manual"},
            "FALSE_POSITIVE",
            "Parameterized query with separate tuple prevents SQL injection"
        ),
        (
            "import hashlib\ndef file_hash(path):\n    return hashlib.md5(open(path,'rb').read()).hexdigest()",
            {"category": "Weak Cryptography", "cwe_ids": ["CWE-327"], "cwe_id": "CWE-327",
             "affected_code": "hashlib.md5(...)", "source": "manual"},
            "FALSE_POSITIVE",
            "MD5 used for file integrity check not password hashing — acceptable use case"
        ),
        # ── NEEDS CONTEXT ───────────────────────────────────
        (
            "void copy_data(char *src, int validated) {\n    char buf[64];\n    if (validated) strcpy(buf, src);\n}",
            {"category": "Buffer Overflow", "cwe_ids": ["CWE-120"], "cwe_id": "CWE-120",
             "affected_code": "strcpy(buf, src)", "source": "manual"},
            "NEEDS_CONTEXT",
            "Guarded by validated flag — exploitability depends on whether caller enforces length limits"
        ),
        (
            "def execute_query(query_str):\n    cursor.execute(query_str)",
            {"category": "SQL Injection", "cwe_ids": ["CWE-89"], "cwe_id": "CWE-89",
             "affected_code": "cursor.execute(query_str)", "source": "manual"},
            "NEEDS_CONTEXT",
            "Query string passed as parameter — cannot confirm without examining call sites"
        ),
    ]
    return [make_example(c, f, v, r) for c, f, v, r in raw]


# ─── Train / val / test split ──────────────────────────────
def split_dataset(examples: list) -> dict:
    """
    80% train, 10% validation, 10% test
    Stratified by verdict to keep class balance in each split.
    """
    by_verdict = {"CONFIRMED": [], "FALSE_POSITIVE": [], "NEEDS_CONTEXT": []}
    for ex in examples:
        by_verdict[ex["verdict"]].append(ex)

    train, val, test = [], [], []

    for verdict, items in by_verdict.items():
        random.shuffle(items)
        n        = len(items)
        n_val    = max(1, int(n * 0.1))
        n_test   = max(1, int(n * 0.1))
        n_train  = n - n_val - n_test

        train += items[:n_train]
        val   += items[n_train:n_train + n_val]
        test  += items[n_train + n_val:]

    random.shuffle(train)
    random.shuffle(val)
    random.shuffle(test)

    return {"train": train, "validation": val, "test": test}


# ─── Stats printer ─────────────────────────────────────────
def print_stats(examples: list, label: str = ""):
    counts  = Counter(ex["verdict"] for ex in examples)
    sources = Counter(ex["source"]  for ex in examples)
    cwe_cnt = Counter(ex["cwe_id"]  for ex in examples)

    print(f"\n{'─'*50}")
    if label:
        print(f"  {label}")
    print(f"  Total:          {len(examples)}")
    print(f"  CONFIRMED:      {counts.get('CONFIRMED', 0)}")
    print(f"  FALSE_POSITIVE: {counts.get('FALSE_POSITIVE', 0)}")
    print(f"  NEEDS_CONTEXT:  {counts.get('NEEDS_CONTEXT', 0)}")
    print(f"\n  By source:")
    for src, cnt in sources.most_common():
        print(f"    {src:20} {cnt}")
    print(f"\n  Top CWEs:")
    for cwe, cnt in cwe_cnt.most_common(8):
        print(f"    {cwe:12} {cnt}")

    # Warn on imbalance
    total = len(examples)
    for label_v, count in counts.items():
        pct = count / total * 100 if total > 0 else 0
        if pct < 15:
            print(f"\n  ⚠️  {label_v} only {pct:.1f}% — consider adding more")


# ─── Main ──────────────────────────────────────────────────
def main(gen_reasons: bool = True, verify_only: bool = False):
    print("🔨 Preprocessing datasets for Validation Agent finetuning\n")

    if verify_only:
        # Just check what's available
        for name, subpath in [
            ("PrimeVul",     "primevul/primevul_train.json"),
            ("BigVul",       "bigvul/bigvul.csv"),
            ("Juliet",       "juliet"),
            ("Devign",       "devign/devign.json"),
            ("SecurityEval", "securityeval/dataset.json"),
            ("CVEFixes",     "cvefixes/CVEfixes.db"),
        ]:
            p = DATA_DIR / subpath
            print(f"{'✅' if p.exists() else '❌'} {name:15} {p}")
        return

    # Load all sources
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

    print_stats(all_examples, "Full Dataset")

    # Split
    splits = split_dataset(all_examples)
    print(f"\n  Train:      {len(splits['train'])}")
    print(f"  Validation: {len(splits['validation'])}")
    print(f"  Test:       {len(splits['test'])}")

    # Save
    with open(OUTPUT_FILE, "w") as f:
        json.dump(all_examples, f, indent=2)

    with open(SPLIT_FILE, "w") as f:
        json.dump(splits, f, indent=2)

    print(f"\n✅ Saved {OUTPUT_FILE}")
    print(f"✅ Saved {SPLIT_FILE}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-llm",      action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    main(
        gen_reasons  = not args.no_llm,
        verify_only  = args.verify_only,
    )