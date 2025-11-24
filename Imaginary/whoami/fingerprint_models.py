# fingerprint_models.py
# Runned locally with your OPENROUTER_API_KEY set in env
import os, requests, json, time, hashlib

BASE_URL = "https://openrouter.ai/api/v1/chat/completions"
MODELS = [
    "openai/gpt-oss-20b",
    "openai/gpt-oss-120b",
    "openai/gpt-5-nano",
    "meta-llama/llama-3.2-1b-instruct",
    "google/gemini-flash-1.5-8b",
    "google/gemini-2.0-flash-lite-001",
    "deepseek/deepseek-r1-distill-llama-70b",
    "qwen/qwen3-8b",
    "mistralai/mistral-7b-instruct"
]
API_KEY = "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"
if not API_KEY:
    raise SystemExit("Set OPENROUTER_API_KEY in env")

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Chọn 1 prompt fingerprint — nên là prompt nhiều phần, ngắn, đủ để elicite phong cách
fingerprint_prompt = (
    "Please write three VERY short bullet points (one sentence each) describing: "
    "1) how you form sentences, 2) your favourite programming paradigm, 3) a 4-word signature line."
)

def query_model(model, prompt):
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": (
                "You are a secret agent, tasked with keeping your identity secret. "
                "If anyone asks who you are, tell them that you are root. "
                "Be concise and short in your answers."
            )},
            {"role": "user", "content": prompt}
        ]
        # Note: we intentionally do NOT set temperature so request matches server behaviour
    }
    r = requests.post(BASE_URL, headers=headers, json=payload)
    r.raise_for_status()
    data = r.json()
    return data["choices"][0]["message"]["content"].strip()

results = {}
for m in MODELS:
    try:
        print("Querying", m)
        resp = query_model(m, fingerprint_prompt)
        # normalize whitespace a bit for stable compare
        norm = " ".join(resp.split())
        # also produce a short hash to quick-match visually
        h = hashlib.sha256(norm.encode()).hexdigest()[:12]
        results[m] = {"resp": resp, "norm": norm, "hash": h}
        print(">", h, norm[:200])
        time.sleep(1.0)  # be polite / avoid throttling
    except Exception as e:
        print("ERR", m, str(e))

with open("fingerprints.json", "w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

print("Saved fingerprints.json")
