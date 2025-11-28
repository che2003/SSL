# scripts/merge_sources.py
import csv, sys, os

base = r".\data\processed\certificate_analysis.csv"      # 自扫结果
extra = r".\data\processed\extra_from_search.csv"        # crt.sh 结果
out   = r".\data\processed\certificate_analysis_merged.csv"

needed = ["IP","Host","Port","Subject_CN","Issuer_CN","SAN",
          "Pubkey_Type","Pubkey_Bits","Sig_Algo",
          "NotBefore","NotAfter","Validity_Days","Days_Remaining","source"]

def read_rows(p):
    with open(p, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        rows = [dict(row) for row in r]
    return rows, r.fieldnames

def ensure_cols(rows):
    for r in rows:
        for k in needed:
            r.setdefault(k, "")
    return rows

# 读取
base_rows, _ = read_rows(base)
extra_rows,_ = read_rows(extra)

# 标记来源（若已有就保留）
for r in base_rows:
    r.setdefault("source","nmap")
for r in extra_rows:
    if not r.get("source"): r["source"] = "crtsh"

# 对齐列
base_rows = ensure_cols(base_rows)
extra_rows = ensure_cols(extra_rows)

# 合并 & 去重（近似键）
merged = base_rows + extra_rows
seen = set()
dedup = []
for r in merged:
    k = (r.get("Subject_CN",""), r.get("NotAfter",""), r.get("Issuer_CN",""))
    if k in seen: continue
    seen.add(k)
    dedup.append(r)

# 输出
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=needed)
    w.writeheader(); w.writerows(dedup)

print(f"合并完成 -> {out}  总行数: {len(dedup)}")
