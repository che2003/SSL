# normalize_crtsh_json.py
import json, csv

IN  = "data/raw/crt_edu.json"           # 如果你用的是别的文件名，改这里
OUT = "data/processed/extra_from_search.csv"

def norm_issuer(s):
    # issuer_name 通常是 "/C=US/O=Let's Encrypt/CN=R3" 这种，可简单提 CN
    if not s: return ""
    parts = s.split("/")
    kv = {}
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv.get("CN", s)  # 尽量取 CN, 取不到就保留原串

with open(IN, "r", encoding="utf-8") as f:
    data = json.load(f)  # crt.sh 输出通常是 JSON 数组

rows = []
for item in data:
    subj = item.get("common_name", "") or ""
    issuer_raw = item.get("issuer_name", "") or ""
    issuer = norm_issuer(issuer_raw)
    not_after = item.get("not_after", "") or ""
    name_value = item.get("name_value", "") or ""
    # name_value 可能是多行，把换行替换为分号
    san = ";".join([s.strip() for s in name_value.replace("\r","").split("\n") if s.strip()])

    rows.append({
        "IP": "",  # crt.sh 通常没有 IP
        "Subject_CN": subj,
        "Issuer_CN": issuer,
        "Sig_Algo": "",         # crt.sh 不一定提供，留空无妨
        "Pubkey_Type": "",      # 同上
        "Pubkey_Bits": "",      # 同上
        "NotAfter": not_after,
        "SAN": san,
        "source": "crtsh",
    })

# 去重（按 Subject_CN + NotAfter + Issuer_CN 近似）
seen = set()
deduped = []
for r in rows:
    k = (r["Subject_CN"], r["NotAfter"], r["Issuer_CN"])
    if k in seen:
        continue
    seen.add(k)
    deduped.append(r)

with open(OUT, "w", newline="", encoding="utf-8") as g:
    w = csv.DictWriter(g, fieldnames=["IP","Subject_CN","Issuer_CN","Sig_Algo","Pubkey_Type","Pubkey_Bits","NotAfter","SAN","source"])
    w.writeheader()
    w.writerows(deduped)

print(f"Wrote {OUT} with {len(deduped)} rows.")
