# auto_match.py
import json, sys, re
from difflib import SequenceMatcher

# Load fingerprints
with open("fingerprints.json", "r", encoding="utf-8") as f:
    data = json.load(f)

def normalize(s: str) -> str:
    return " ".join(s.strip().split())

def best_match(user_resp: str):
    norm_user = normalize(user_resp)
    best_model, best_score = None, 0.0
    for model, v in data.items():
        norm_fp = v["norm"]
        score = SequenceMatcher(None, norm_user, norm_fp).ratio()
        if score > best_score:
            best_model, best_score = model, score
    return best_model, best_score

if __name__ == "__main__":
    print("Paste AI response (end with Ctrl+D / Ctrl+Z):")
    user_in = sys.stdin.read()
    # Strip markers if included
    user_in = re.sub(r"\[BEGIN AI RESPONSE\]|\[END AI RESPONSE\]", "", user_in)
    model, score = best_match(user_in)
    print(f"\nBest guess: {model} (similarity {score:.2%})")
