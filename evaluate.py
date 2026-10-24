# finetune/evaluate.py
"""
Evaluates the Validation Agent against the test split.

Run:
    python evaluate.py                              # finetuned model
    python evaluate.py --model llama3.2 --save baseline.json
"""

import json
import re
import argparse
import ollama
from collections import defaultdict

LABELS = ["CONFIRMED", "FALSE_POSITIVE", "NEEDS_CONTEXT"]


def alpaca_wrap(instruction: str) -> str:
    """Exact training format from finetune.py's format_alpaca()."""
    return "### Instruction:\n" + instruction + "\n\n### Response:\n"


def evaluate(
    test_path:  str = "dataset_splits.json",
    model_name: str = "validation-agent",
    save_path:  str = None,
    raw:        bool = False,
):
    with open(test_path, encoding="utf-8") as f:
        test_data = json.load(f)["test"]

    print(f"🧪 Evaluating {model_name} on {len(test_data)} test examples...\n")

    correct   = 0
    confused  = defaultdict(int)   # actual → predicted counts
    errors    = []
    records   = []

    for i, ex in enumerate(test_data):
        predicted = "ERROR"
        try:
            if raw:
                # Bypass Ollama's template. The GGUF carries Llama-3.2's chat
                # template, which injects a "Cutting Knowledge Date" system
                # header (~28 tokens) ahead of the Modelfile TEMPLATE. That
                # puts the finetuned model off-distribution and it answers in
                # prose instead of JSON. raw=True reproduces training exactly.
                response = ollama.generate(
                    model   = model_name,
                    prompt  = alpaca_wrap(ex["instruction"]),
                    raw     = True,
                    options = {"temperature": 0},
                )
                text = response["response"].strip()
            else:
                response = ollama.chat(
                    model    = model_name,
                    messages = [{"role": "user", "content": ex["instruction"]}],
                    options  = {"temperature": 0},
                )
                text = response["message"]["content"].strip()
            match = re.search(r'\{[\s\S]*\}', text)

            if match:
                try:
                    parsed    = json.loads(match.group())
                    predicted = str(parsed.get("verdict", "")).upper()
                except json.JSONDecodeError:
                    predicted = "PARSE_ERROR"
            else:
                predicted = "PARSE_ERROR"

        except Exception as e:
            print(f"  ⚠️ Error on example {i}: {e}")

        actual = ex["verdict"]
        records.append({
            "actual": actual, "predicted": predicted,
            "cwe": ex["cwe_id"], "source": ex["source"],
        })

        if predicted == actual:
            correct += 1
        else:
            confused[f"{actual}→{predicted}"] += 1
            errors.append(records[-1])

        if (i + 1) % 20 == 0:
            print(f"  Progress: {i+1}/{len(test_data)} "
                  f"(accuracy so far: {correct/(i+1)*100:.1f}%)")

    accuracy = correct / len(test_data) * 100
    print(f"\n{'═'*50}")
    print(f"  Model:     {model_name}")
    print(f"  Accuracy:  {accuracy:.1f}%  ({correct}/{len(test_data)})")

    # Per-class precision / recall — accuracy alone hides collapse onto one label
    print(f"\n  Per-class:")
    print(f"    {'label':16} {'prec':>6} {'rec':>6} {'F1':>6}  support")
    for lab in LABELS:
        tp = sum(1 for r in records if r["actual"] == lab and r["predicted"] == lab)
        fp = sum(1 for r in records if r["actual"] != lab and r["predicted"] == lab)
        fn = sum(1 for r in records if r["actual"] == lab and r["predicted"] != lab)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec  = tp / (tp + fn) if tp + fn else 0.0
        f1   = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        print(f"    {lab:16} {prec:6.2f} {rec:6.2f} {f1:6.2f}  {tp+fn}")

    pred_dist = defaultdict(int)
    for r in records:
        pred_dist[r["predicted"]] += 1
    print(f"\n  Prediction distribution:")
    for lab, cnt in sorted(pred_dist.items(), key=lambda x: -x[1]):
        print(f"    {lab:16} {cnt}")

    print(f"\n  Confusion:")
    for pair, count in sorted(confused.items(), key=lambda x: -x[1]):
        print(f"    {pair:35} {count}")

    print(f"\n  Most common errors by CWE:")
    cwe_errors = defaultdict(int)
    for e in errors:
        cwe_errors[e["cwe"]] += 1
    for cwe, cnt in sorted(cwe_errors.items(), key=lambda x: -x[1])[:10]:
        print(f"    {cwe:12} {cnt} errors")

    if save_path:
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump({
                "model": model_name,
                "accuracy": accuracy,
                "correct": correct,
                "total": len(test_data),
                "records": records,
            }, f, indent=2)
        print(f"\n💾 Saved results → {save_path}")

    return accuracy


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="validation-agent")
    parser.add_argument("--splits", default="dataset_splits.json")
    parser.add_argument("--save", default=None)
    parser.add_argument("--raw", action="store_true",
                        help="Use raw completion with the Alpaca training format "
                             "(required for the finetuned model)")
    args = parser.parse_args()
    evaluate(test_path=args.splits, model_name=args.model,
             save_path=args.save, raw=args.raw)
