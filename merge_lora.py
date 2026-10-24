"""Merge the shipped LoRA adapter into the base model, producing ./validation_agent_merged
(the directory the Modelfile expects). CPU-friendly alternative to re-running finetune.py.

    pip install torch transformers peft
    python merge_lora.py
"""
import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

BASE = "unsloth/Llama-3.2-3B-Instruct"
LORA = "validation_agent_lora"
OUT = "validation_agent_merged"

model = AutoModelForCausalLM.from_pretrained(BASE, torch_dtype=torch.float16)
model = PeftModel.from_pretrained(model, LORA).merge_and_unload()
model.save_pretrained(OUT)
AutoTokenizer.from_pretrained(LORA).save_pretrained(OUT)
print(f"Saved merged model to {OUT}/")
