import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
fails = []
rows = json.load(open(os.path.join(HERE, "data.json")))
for r in rows:
    if r["status"] != "undetermined" and r["shares_tendered"] is None:
        fails.append(r["ticker"])
try:
    open(os.path.join(HERE, "evidence", "receipt.txt")).read()
except OSError as e:
    fails.append(f"COULD NOT LOOK: receipt ({e})")
if fails:
    print("\n".join(fails))
    sys.exit(1)
print("verified")
