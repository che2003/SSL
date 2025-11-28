# scripts/ssl_pipeline.py

import csv, os, sys, argparse, random, re, subprocess, tempfile, urllib.request
from datetime import datetime
import xml.etree.ElementTree as ET

LIST_DIR   = os.path.join("results", "lists")
CHART_DIR  = os.path.join("results", "charts")
REPORT_MD  = os.path.join("results", "REPORT.md")
os.makedirs(LIST_DIR, exist_ok=True)
os.makedirs(CHART_DIR, exist_ok=True)

HAS_MPL = False
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MPL = True
    from matplotlib import font_manager
    for fp in [r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\msyh.ttf",
               r"C:\Windows\Fonts\simhei.ttf", r"C:\Windows\Fonts\simsun.ttc"]:
        if os.path.exists(fp):
            font_manager.fontManager.addfont(fp)
            matplotlib.rcParams["font.family"] = font_manager.FontProperties(fname=fp).get_name()
            break
    matplotlib.rcParams["axes.unicode_minus"] = False
    plt.rcParams.update({
        "figure.dpi": 140, "savefig.dpi": 140,
        "font.size": 11, "axes.titlesize": 14, "axes.labelsize": 12,
        "xtick.labelsize": 10, "ytick.labelsize": 10,
        "axes.grid": True, "grid.alpha": 0.25, "grid.linestyle": "--",
        "axes.spines.top": False, "axes.spines.right": False,
    })
except Exception:
    HAS_MPL = False

def read_csv_rows(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append({k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()})
    return rows

def write_csv(path, rows):
    if not rows: return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader(); w.writerows(rows)

def to_int(x, default=None):
    try: return int(float(x))
    except: return default

def counter(rows, key):
    cnt = {}
    for r in rows:
        k = (r.get(key) or "").strip()
        cnt[k] = cnt.get(k, 0) + 1
    return cnt

def counter_topn(rows, key, n=10):
    c = counter(rows, key)
    return sorted(c.items(), key=lambda kv: kv[1], reverse=True)[:n]

def ensure_columns(rows, needed):
    for r in rows:
        for k in needed: r.setdefault(k, "")
    return rows

def merge_and_dedupe(base_rows, extra_rows):
    all_cols = set()
    for r in base_rows + extra_rows: all_cols.update(r.keys())
    all_cols = list(all_cols)
    for r in base_rows + extra_rows:
        for c in all_cols: r.setdefault(c, "")
    for r in base_rows:
        if not r.get("source"): r["source"] = "nmap"
    for r in extra_rows:
        if not r.get("source"): r["source"] = "crtsh"
    merged = base_rows + extra_rows
    key_map = {}
    for r in merged:
        k = f"{r.get('Subject_CN','')}|{r.get('NotAfter','')}|{r.get('Issuer_CN','')}"
        if k not in key_map: key_map[k] = r
    return list(key_map.values())

def compute_overview(rows):
    total = len(rows)
    ips = {r.get("IP","") for r in rows if r.get("IP")}
    subjects = {r.get("Subject_CN","") for r in rows if r.get("Subject_CN")}
    expired, expiring_30 = [], []
    for r in rows:
        dr = to_int(r.get("Days_Remaining"))
        if dr is None: continue
        if dr < 0: expired.append(r)
        elif dr <= 30: expiring_30.append(r)
    return {
        "total": total,
        "unique_ips": len(ips),
        "unique_subjects": len(subjects),
        "expired": len(expired),
        "expiring_30": len(expiring_30),
        "expired_rows": expired,
        "expiring_rows": expiring_30,
    }

def reuse_by_cert(rows, topk=50):
    k2ips = {}
    for r in rows:
        key = (r.get("Fingerprint") or "").strip()
        if not key:
            key = f"{r.get('Subject_CN','')}|{r.get('NotAfter','')}|{r.get('Issuer_CN','')}"
        ip = r.get("IP","")
        if not key or not ip: continue
        k2ips.setdefault(key, set()).add(ip)
    pairs = sorted(((k, len(v)) for k, v in k2ips.items()), key=lambda x: x[1], reverse=True)
    return [{"Key": k, "unique_IPs": c} for k, c in pairs[:topk]]

def detect_openssl():
    try:
        r = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False

def parse_xml_extract_records(xml_path):
    if not os.path.exists(xml_path): return []
    root = ET.parse(xml_path).getroot()
    records = []
    for host in root.findall(".//host"):
        addr = host.find("address[@addrtype='ipv4']")
        ip = addr.get("addr") if addr is not None else ""
        port = host.find(".//port[@id='443']") or host.find(".//port[@portid='443']")
        if port is None: continue
        script = port.find(".//script[@id='ssl-cert']") or port.find("script[@id='ssl-cert']")
        if script is None: continue
        pem = None; ocsp_url = None; issuer_url = None
        for elem in script.findall(".//elem"):
            if elem.get("key","") == "pem":
                pem = (elem.text or "").replace("&#xa;","\n")
        for table in script.findall(".//table"):
            name_elem = table.find(".//elem[@key='name']")
            val_elem  = table.find(".//elem[@key='value']")
            if name_elem is None or val_elem is None: continue
            name = (name_elem.text or ""); val = (val_elem.text or "")
            if "Authority Information Access" in name or "AIA" in name:
                m = re.search(r"OCSP.*?URI:([^\s]+)", val)
                if m: ocsp_url = m.group(1)
                m = re.search(r"CA Issuers\s*-\s*URI:([^\s]+)", val)
                if m: issuer_url = m.group(1)
        if pem: records.append({"ip": ip, "pem": pem, "ocsp": ocsp_url, "issuer": issuer_url})
    return records

def ocsp_check_sample(xml_path, sample_n=100):
    if sample_n <= 0: return {"status_count": {}, "rows": [], "note": "skip"}
    if not detect_openssl(): return {"status_count": {}, "rows": [], "note": "openssl_not_found"}
    recs = parse_xml_extract_records(xml_path)
    if not recs: return {"status_count": {}, "rows": [], "note": "no_records_from_xml"}
    results = []
    sample = random.sample(recs, min(sample_n, len(recs)))
    for rec in sample:
        status, note = "unknown", ""
        try:
            with tempfile.TemporaryDirectory() as td:
                leaf = os.path.join(td, "leaf.pem")
                with open(leaf, "w", encoding="utf-8") as f: f.write(rec["pem"])
                issuer_pem = os.path.join(td, "issuer.pem")
                if rec.get("issuer") and rec["issuer"].startswith("http"):
                    try: urllib.request.urlretrieve(rec["issuer"], issuer_pem)
                    except Exception as e: note = f"issuer_download_fail:{e}"
                else:
                    note = "no_issuer_url"
                if rec.get("ocsp") and os.path.exists(issuer_pem):
                    cmd = ["openssl","ocsp","-issuer",issuer_pem,"-cert",leaf,"-url",rec["ocsp"],"-resp_text","-noverify"]
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
                    out = (r.stdout + "\n" + r.stderr).lower()
                    if "revoked" in out: status = "revoked"
                    elif "good" in out: status = "good"
                    else: status = "unknown"
                    if not note: note = out[:200]
                else:
                    if not rec.get("ocsp"): note = (note + "; no_ocsp_url").strip("; ")
        except Exception as e:
            status, note = "error", str(e)
        results.append({"ip": rec.get("ip",""), "status": status, "note": note})
    sc = {}
    for r in results: sc[r["status"]] = sc.get(r["status"], 0) + 1
    return {"status_count": sc, "rows": results, "note": ""}

def percent(num, den): return f"{(num/den*100):.1f}%" if den else "0.0%"

from textwrap import wrap
BAR_COLORS = ["#4C78A8"] * 10
PIE_COLORS = ["#59A14F", "#F28E2B", "#E15759", "#EDC948", "#B07AA1", "#76B7B2"]
ACCENT_COLOR = "#4C78A8"

def _wrap_labels(labels, width=18):
    return ["\n".join(wrap(str(x), width=width)) for x in labels]

def save_bar_chart(pairs, title, xlabel, filename, rotate_xticks=True):
    if not HAS_MPL or not pairs: return False
    pairs = sorted(pairs, key=lambda kv: kv[1], reverse=True)
    labels = [("(空)" if (k is None or k == "") else str(k)) for k, _ in pairs]
    labels_wrapped = _wrap_labels(labels, width=20)
    values = [v for _, v in pairs]
    plt.figure(figsize=(11, 5.5))
    bars = plt.bar(range(len(values)), values, color=BAR_COLORS[:len(values)])
    for i, b in enumerate(bars):
        plt.text(b.get_x() + b.get_width() / 2, b.get_height(), f"{values[i]}",
                 ha="center", va="bottom", fontsize=9, color="#333")
    plt.title(title, pad=10); plt.xlabel(xlabel); plt.ylabel("Count")
    plt.xticks(range(len(values)), labels_wrapped, rotation=0 if not rotate_xticks else 0, ha="center")
    plt.tight_layout()
    outpng = os.path.join(CHART_DIR, filename)
    plt.savefig(outpng, bbox_inches="tight"); plt.close()
    return True

def save_pie_chart(labels_counts, title, filename):
    if not HAS_MPL or not labels_counts: return False
    labels_counts = [(("(空)" if (lbl is None or lbl == "") else str(lbl)), cnt)
                     for lbl, cnt in labels_counts if cnt > 0]
    if not labels_counts: return False
    labels = [lbl for lbl, _ in labels_counts]; sizes = [cnt for _, cnt in labels_counts]
    def autopct(pct): return "<0.1%" if pct < 0.1 else f"{pct:.1f}%"
    explode = [0.03] + [0]* (len(sizes)-1)
    plt.figure(figsize=(7, 7))
    wedges, texts, autotexts = plt.pie(
        sizes, labels=labels, autopct=autopct, startangle=90,
        explode=explode, pctdistance=0.75, labeldistance=1.05,
        colors=PIE_COLORS[:len(sizes)], shadow=True
    )
    for t in texts: t.set_fontsize(10)
    for a in autotexts: a.set_color("white"); a.set_fontsize(10); a.set_weight("bold")
    plt.title(title, pad=12); plt.tight_layout()
    outpng = os.path.join(CHART_DIR, filename)
    plt.savefig(outpng, bbox_inches="tight"); plt.close()
    return True

def save_histogram(values, title, xlabel, filename, bins=30):
    if not HAS_MPL or not values: return False
    plt.figure(figsize=(10, 5.5))
    plt.hist(values, bins=bins, color=ACCENT_COLOR, edgecolor="white")
    plt.title(title, pad=10); plt.xlabel(xlabel); plt.ylabel("Frequency")
    plt.tight_layout()
    outpng = os.path.join(CHART_DIR, filename)
    plt.savefig(outpng, bbox_inches="tight"); plt.close()
    return True

def main():
    parser = argparse.ArgumentParser(description="SSL/TLS pipeline")
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--xml", required=False, default=os.path.join("data","raw","final_certs.xml"))
    parser.add_argument("--extra", required=False)
    parser.add_argument("--sample", type=int, default=0)
    parser.add_argument("--ext-cap", type=float, default=0.3)
    args = parser.parse_args()

    needed_cols = ["IP","Host","Port","Subject_CN","Issuer_CN","SAN",
                   "Pubkey_Type","Pubkey_Bits","Sig_Algo",
                   "NotBefore","NotAfter","Validity_Days","Days_Remaining",
                   "Fingerprint","source"]

    base_rows = ensure_columns(read_csv_rows(args.input_csv), needed_cols)
    for r in base_rows:
        if not r.get("source"): r["source"] = "nmap"
    overview1 = compute_overview(base_rows)
    write_csv(os.path.join(LIST_DIR, "list_expired.csv"), overview1["expired_rows"])
    write_csv(os.path.join(LIST_DIR, "list_expiring_30d.csv"), overview1["expiring_rows"])

    merged_rows = base_rows
    merged_csv_path = os.path.join(LIST_DIR, "dataset_merged.csv")
    merged_info = "No external file provided; merged set equals scan-derived set."
    if args.extra and os.path.exists(args.extra):
        extra_rows = ensure_columns(read_csv_rows(args.extra), needed_cols)
        merged_rows = merge_and_dedupe(base_rows, extra_rows)
        merged_info = f"Merged external rows: {len(extra_rows)}; de-duped total: {len(merged_rows)}."
    write_csv(merged_csv_path, merged_rows)

    reuse_top = reuse_by_cert(merged_rows, topk=50)
    write_csv(os.path.join(LIST_DIR, "cert_reuse_top50.csv"), reuse_top)

    ov_merged = compute_overview(merged_rows)
    top_issuer   = counter_topn(merged_rows, "Issuer_CN", 10)
    top_sig      = counter_topn(merged_rows, "Sig_Algo", 10)
    top_keytype  = counter_topn(merged_rows, "Pubkey_Type", 10)
    top_bits     = counter_topn(merged_rows, "Pubkey_Bits", 10)

    nmap_rows  = [r for r in merged_rows if (r.get("source") or "").lower() == "nmap"]
    ext_rows   = [r for r in merged_rows if (r.get("source") or "").lower() != "nmap"]

    if HAS_MPL:
        save_bar_chart(counter_topn(nmap_rows, "Issuer_CN", 10), "Issuer Top 10 (nmap-only)", "Issuer_CN", "chart_issuer_top10_nmap.png")
        save_bar_chart(counter_topn(nmap_rows, "Sig_Algo", 10), "Signature Algorithm Top 10 (nmap-only)", "Sig_Algo", "chart_sig_algo_top10_nmap.png")
        save_bar_chart(counter_topn(nmap_rows, "Pubkey_Type", 10), "Public Key Type Top 10 (nmap-only)", "Pubkey_Type", "chart_pubkey_type_top10_nmap.png")
        save_bar_chart(counter_topn(nmap_rows, "Pubkey_Bits", 10), "Public Key Bits Top 10 (nmap-only)", "Pubkey_Bits", "chart_pubkey_bits_top10_nmap.png")

    balanced_rows = list(nmap_rows)
    if ext_rows and args.ext_cap > 0:
        cap = min(len(nmap_rows), int(len(nmap_rows) * args.ext_cap))
        ext_rows_sampled = random.sample(ext_rows, cap) if len(ext_rows) > cap else ext_rows
        balanced_rows += ext_rows_sampled

    if HAS_MPL:
        save_bar_chart(counter_topn(balanced_rows, "Issuer_CN", 10), "Issuer Top 10 (balanced)", "Issuer_CN", "chart_issuer_top10_balanced.png")
        save_bar_chart(counter_topn(balanced_rows, "Sig_Algo", 10), "Signature Algorithm Top 10 (balanced)", "Sig_Algo", "chart_sig_algo_top10_balanced.png")
        save_bar_chart(counter_topn(balanced_rows, "Pubkey_Type", 10), "Public Key Type Top 10 (balanced)", "Pubkey_Type", "chart_pubkey_type_top10_balanced.png")
        save_bar_chart(counter_topn(balanced_rows, "Pubkey_Bits", 10), "Public Key Bits Top 10 (balanced)", "Pubkey_Bits", "chart_pubkey_bits_top10_balanced.png")

    ocsp_note = "not run"
    ocsp_result = {"status_count": {}, "rows": []}
    if args.sample and args.sample > 0:
        ocsp_result = ocsp_check_sample(args.xml, sample_n=args.sample)
        write_csv(os.path.join(LIST_DIR, "revocation_sample_result.csv"), ocsp_result["rows"])
        ocsp_note = ocsp_result["note"] or "done"

    charts = []
    if HAS_MPL:
        if save_bar_chart(top_issuer, "Issuer Top 10", "Issuer_CN", "chart_issuer_top10.png"): charts.append("chart_issuer_top10.png")
        if save_bar_chart(top_sig, "Signature Algorithm Top 10", "Sig_Algo", "chart_sig_algo_top10.png"): charts.append("chart_sig_algo_top10.png")
        if save_bar_chart(top_keytype, "Public Key Type Top 10", "Pubkey_Type", "chart_pubkey_type_top10.png"): charts.append("chart_pubkey_type_top10.png")
        if save_bar_chart(top_bits, "Public Key Bits Top 10", "Pubkey_Bits", "chart_pubkey_bits_top10.png"): charts.append("chart_pubkey_bits_top10.png")
        exp = ov_merged["expired"]; exp30 = ov_merged["expiring_30"]; ok = ov_merged["total"] - exp - exp30
        if save_pie_chart([("Valid", ok), ("Expiring (<=30d)", exp30), ("Expired", exp)], "Certificate Validity Status", "chart_expiry_pie.png"):
            charts.append("chart_expiry_pie.png")
        dr_values = []
        for r in merged_rows:
            v = to_int(r.get("Days_Remaining"))
            if v is not None: dr_values.append(v)
        if dr_values and save_histogram(dr_values, "Days Remaining Histogram", "Days_Remaining", "chart_days_remaining_hist.png", bins=30):
            charts.append("chart_days_remaining_hist.png")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    def fmt_top(lst): return "\n".join([f"- {k or '(空)'}：{v}" for k,v in lst]) if lst else "(无数据)"
    exp = ov_merged["expired"]; exp30 = ov_merged["expiring_30"]; ok = ov_merged["total"] - exp - exp30
    sc = ocsp_result["status_count"]; total_ocsp = sum(sc.values()) if sc else 0
    good = sc.get("good",0) if sc else 0; revoked = sc.get("revoked",0) if sc else 0
    unknown = sc.get("unknown",0) if sc else 0; error = sc.get("error",0) if sc else 0
    def pct(x): return f"{(x/total_ocsp*100):.1f}%" if total_ocsp else "0.0%"

    report = []
    report.append(f"# Project 1 — Analyzing SSL/TLS Certificates Used by Real Web Sites\n\nGenerated: {now}\n")
    report.append("## 1) Create a tool or use existing tool to scan 1K HTTPS sites and collect their certificates\n")
    report.append("- Used Nmap `--script ssl-cert` against ~1K targets; open 443 hosts parsed into `data/processed/certificate_analysis.csv`.")
    report.append(f"- Initial dataset: **{overview1['total']}** rows; unique IPs **{overview1['unique_ips']}**, unique subjects **{overview1['unique_subjects']}**.\n")
    report.append("## 2) Use existing security search engine to collect more certificates\n")
    if args.extra and os.path.exists(args.extra):
        report.append(f"- Augmented with crt.sh export `data/processed/extra_from_search.csv`. {merged_info}\n")
    else:
        report.append("- No external file provided in this run; merged set equals the scan-derived set.\n")
    report.append("## 3) Analyze the hosts sending back the certificates\n")
    report.append("- Certificate reuse computed by SHA-256 fingerprint (fallback to CN|Issuer|NotAfter). Output: `results/lists/cert_reuse_top50.csv`.")
    if reuse_top: report.append(f"- Top example: `{reuse_top[0]['Key']}` used by **{reuse_top[0]['unique_IPs']}** distinct IPs.\n")
    else: report.append("- No reuse found.\n")
    report.append("## 4) Analyze the properties of certificates\n")
    report.append("**Issuers (Top 10)**\n" + fmt_top(top_issuer) + "\n![](charts/chart_issuer_top10.png)\n")
    report.append("**Signature Algorithms (Top 10)**\n" + fmt_top(top_sig) + "\n![](charts/chart_sig_algo_top10.png)\n")
    report.append("**Public Key Types (Top 10)**\n" + fmt_top(top_keytype) + "\n![](charts/chart_pubkey_type_top10.png)\n")
    report.append("**Public Key Bits (Top 10)**\n" + fmt_top(top_bits) + "\n![](charts/chart_pubkey_bits_top10.png)\n")
    report.append("**Expiry status**\n![](charts/chart_expiry_pie.png)\n")
    report.append("**Days remaining histogram**\n![](charts/chart_days_remaining_hist.png)\n")
    report.append("- Detailed lists: `results/lists/list_expired.csv`, `results/lists/list_expiring_30d.csv`.\n")
    report.append("## 5) Measure the certificate revocation of web sites\n")
    if total_ocsp:
        report.append(f"- OCSP sampled **{total_ocsp}**: good={good} ({pct(good)}), revoked={revoked} ({pct(revoked)}), unknown={unknown} ({pct(unknown)}), error={error} ({pct(error)}).")
        report.append("- Raw results: `results/lists/revocation_sample_result.csv`.\n")
    else:
        report.append(f"- OCSP not executed or empty in this run ({ocsp_note}).\n")
    report.append("---\n### Appendix — Source-stratified & balanced views\n")
    report.append("- Additional charts: `*_nmap.png` (nmap-only) and `*_balanced.png` (balanced with external cap).")
    with open(REPORT_MD, "w", encoding="utf-8") as f: f.write("\n".join(report))

    print("✅ Done")
    for fp in [
        os.path.join(LIST_DIR, "list_expired.csv"),
        os.path.join(LIST_DIR, "list_expiring_30d.csv"),
        merged_csv_path,
        os.path.join(LIST_DIR, "cert_reuse_top50.csv"),
        os.path.join(LIST_DIR, "revocation_sample_result.csv") if args.sample>0 else "",
        REPORT_MD,
    ]:
        if fp and os.path.exists(fp): print(" -", fp)
    if HAS_MPL: print(" - charts ->", CHART_DIR)

if __name__ == "__main__":
    main()

# python .\scripts\ssl_pipeline.py --input-csv .\data\processed\certificate_analysis.csv --xml .\data\raw\final_certs.xml --extra .\data\processed\extra_from_search.csv --sample 100 --ext-cap 0.1
