# finetune/finetune.py
"""
Finetunes llama3.2-3B for the Validation Agent using Unsloth + QLoRA.

Run:
    python finetune.py                    # full finetune
    python finetune.py --epochs 1         # quick test run
"""

import json
import argparse

MAX_SEQ_LENGTH = 2048
SEED           = 42


def load_splits(path: str = "dataset_splits.json"):
    from datasets import Dataset
    with open(path, encoding="utf-8") as f:
        splits = json.load(f)
    return (
        Dataset.from_list(splits["train"]),
        Dataset.from_list(splits["validation"]),
    )


def make_formatter(eos_token: str):
    """
    Alpaca format, matching the TEMPLATE in Modelfile.

    The EOS token is mandatory: without it the model never learns where a
    response ends and generation runs on past the JSON verdict.
    """
    def format_alpaca(example: dict) -> dict:
        return {
            "text": (
                f"### Instruction:\n{example['instruction']}\n\n"
                f"### Response:\n{example['output']}{eos_token}"
            )
        }
    return format_alpaca


def finetune(epochs: int = 3, export_gguf: bool = True):
    from unsloth import FastLanguageModel
    from trl import SFTTrainer, SFTConfig
    import torch

    print("🚀 Loading base model...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name     = "unsloth/Llama-3.2-3B-Instruct",
        max_seq_length = MAX_SEQ_LENGTH,
        load_in_4bit   = True,
    )

    model = FastLanguageModel.get_peft_model(
        model,
        r              = 16,
        target_modules = ["q_proj", "k_proj", "v_proj",
                          "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_alpha     = 16,
        lora_dropout   = 0,
        bias           = "none",
        use_gradient_checkpointing = "unsloth",
        random_state   = SEED,
    )

    print("📂 Loading dataset...")
    train_ds, val_ds = load_splits()
    fmt      = make_formatter(tokenizer.eos_token)
    train_ds = train_ds.map(fmt)
    val_ds   = val_ds.map(fmt)
    print(f"   Train: {len(train_ds)}  Val: {len(val_ds)}")
    print(f"   EOS token: {tokenizer.eos_token!r}")

    # bf16 on Ampere+ (this box is a 4090); fp16 only as a fallback.
    use_bf16 = torch.cuda.is_bf16_supported()

    trainer = SFTTrainer(
        model            = model,
        processing_class = tokenizer,
        train_dataset    = train_ds,
        eval_dataset     = val_ds,
        args = SFTConfig(
            dataset_text_field           = "text",
            max_length                   = MAX_SEQ_LENGTH,
            per_device_train_batch_size  = 2,
            per_device_eval_batch_size   = 2,
            gradient_accumulation_steps  = 4,
            warmup_steps                 = 10,
            num_train_epochs             = epochs,
            learning_rate                = 2e-4,
            bf16                         = use_bf16,
            fp16                         = not use_bf16,
            logging_steps                = 10,
            # eval_strategy and save_strategy must match for
            # load_best_model_at_end, and it is eval_strategy in
            # transformers >= 4.46 (evaluation_strategy was removed).
            eval_strategy                = "steps",
            eval_steps                   = 50,
            save_strategy                = "steps",
            save_steps                   = 50,
            save_total_limit             = 2,
            output_dir                   = "checkpoints",
            load_best_model_at_end       = True,
            metric_for_best_model        = "eval_loss",
            greater_is_better            = False,
            seed                         = SEED,
            report_to                    = "none",
        ),
    )

    print(f"\n🏋️ Training for {epochs} epochs (bf16={use_bf16})...")
    trainer.train()

    metrics = trainer.evaluate()
    print(f"\n📉 Final eval_loss: {metrics.get('eval_loss'):.4f}")

    # LoRA adapters always get saved — they are cheap and make the run
    # recoverable if the GGUF conversion below fails.
    model.save_pretrained("validation_agent_lora")
    tokenizer.save_pretrained("validation_agent_lora")
    print("💾 Saved LoRA adapters → validation_agent_lora/")

    if export_gguf:
        # save_pretrained_gguf shells out to llama.cpp, which has no prebuilt
        # Windows bundle — unsloth then tries to `winget install openssl` and
        # build from source, which hangs on a non-interactive terminal.
        # Ollama imports HF safetensors natively for Llama architectures, so
        # the merged fp16 checkpoint below is all `ollama create` needs.
        print("")
        print("💾 Exporting merged fp16 model for Ollama...")
        model.save_pretrained_merged(
            "validation_agent_merged", tokenizer, save_method="merged_16bit"
        )
        print("✅ Saved to validation_agent_merged/")


    print("\nNext:")
    print("  ollama create validation-agent -f Modelfile")
    print("  python evaluate.py --model validation-agent --save finetuned_results.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--no-merge", action="store_true",
                        help="Skip the merged fp16 export (adapters only)")
    args = parser.parse_args()
    finetune(args.epochs, export_gguf=not args.no_merge)
