# scripts/ssl_pipeline.py

import csv, os, argparse, random, re, subprocess, tempfile, urllib.request
import platform
from datetime import datetime
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from textwrap import wrap

# =================配置区域=================
LIST_DIR = os.path.join("results", "lists")
CHART_DIR = os.path.join("results", "charts")
REPORT_MD = os.path.join("results", "REPORT.md")

os.makedirs(LIST_DIR, exist_ok=True)
os.makedirs(CHART_DIR, exist_ok=True)

# =================绘图设置=================
HAS_MPL = False
try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib import font_manager

    HAS_MPL = True

    # --- 跨平台字体自动配置 ---
    system_name = platform.system()
    font_candidates = []
    if system_name == "Windows":
        font_candidates = [r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\simhei.ttf"]
    elif system_name == "Darwin":  # macOS
        font_candidates = ["/System/Library/Fonts/PingFang.ttc", "/Library/Fonts/Arial Unicode.ttf"]
    else:  # Linux
        font_candidates = ["/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
                           "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"]

    font_found = False
    for fp in font_candidates:
        if os.path.exists(fp):
            font_manager.fontManager.addfont(fp)
            matplotlib.rcParams["font.family"] = font_manager.FontProperties(fname=fp).get_name()
            font_found = True
            break

    if not font_found:
        # Fallback
        matplotlib.rcParams['font.family'] = 'sans-serif'

    matplotlib.rcParams["axes.unicode_minus"] = False
    plt.rcParams.update({
        "figure.dpi": 150, "savefig.dpi": 150,
        "font.size": 10, "axes.titlesize": 13, "axes.labelsize": 11,
        "xtick.labelsize": 9, "ytick.labelsize": 9,
        "axes.grid": True, "grid.alpha": 0.3, "grid.linestyle": ":",
        "axes.spines.top": False, "axes.spines.right": False,
    })
except Exception as e:
    HAS_MPL = False

# 美化配色 (Morandi-like colors)
BAR_COLORS = ["#6395FA", "#62DAAB", "#657798", "#F6C02D", "#E96C5B", "#76D0F2", "#9E7FD2", "#FF9D4D", "#3DB6B5",
              "#FF9BBF"]
PIE_COLORS = ["#6395FA", "#62DAAB", "#F6C02D", "#E96C5B", "#657798", "#76D0F2"]


# =================核心功能函数=================

def read_csv_rows(path):
    if not os.path.exists(path): return []
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
        w.writeheader();
        w.writerows(rows)


def to_int(x, default=None):
    try:
        return int(float(x))
    except:
        return default


def counter_topn(rows, key, n=10):
    c = {}
    for r in rows:
        k = (r.get(key) or "").strip()
        # 严格过滤空值
        if not k or k.lower() in ["nan", "none", "null", ""]: continue
        c[k] = c.get(k, 0) + 1
    return sorted(c.items(), key=lambda kv: kv[1], reverse=True)[:n]


def ensure_columns(rows, needed):
    for r in rows:
        for k in needed: r.setdefault(k, "")
    return rows


def merge_and_dedupe(base_rows, extra_rows):
    all_cols = set()
    for r in base_rows + extra_rows: all_cols.update(r.keys())
    for r in base_rows + extra_rows:
        for c in all_cols: r.setdefault(c, "")
    for r in base_rows:
        if not r.get("source"): r["source"] = "nmap"
    for r in extra_rows:
        if not r.get("source"): r["source"] = "crtsh"

    merged = base_rows + extra_rows
    key_map = {}
    for r in merged:
        k = f"{r.get('Subject_CN', '')}|{r.get('NotAfter', '')}|{r.get('Issuer_CN', '')}"
        if k not in key_map:
            key_map[k] = r
        else:
            if r.get("source") == "nmap" and key_map[k].get("source") != "nmap":
                key_map[k] = r
    return list(key_map.values())


def compute_overview(rows):
    total = len(rows)
    ips = {r.get("IP", "") for r in rows if r.get("IP")}
    expired = [];
    expiring_30 = []
    for r in rows:
        dr = to_int(r.get("Days_Remaining"))
        if dr is None: continue
        if dr < 0:
            expired.append(r)
        elif dr <= 30:
            expiring_30.append(r)
    return {
        "total": total,
        "unique_ips": len(ips),
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
            key = f"{r.get('Subject_CN', '')}|{r.get('NotAfter', '')}|{r.get('Issuer_CN', '')}"
        ip = r.get("IP", "")
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


# =================OCSP 检查=================
def parse_xml_extract_records(xml_path):
    if not os.path.exists(xml_path): return []
    try:
        root = ET.parse(xml_path).getroot()
    except:
        return []
    out = []
    for host in root.findall(".//host"):
        addr = host.find("address[@addrtype='ipv4']")
        ip = addr.get("addr") if addr is not None else ""
        script = host.find(".//script[@id='ssl-cert']")
        if script is None: continue

        pem = None;
        ocsp_url = None;
        issuer_url = None
        for elem in script.findall(".//elem"):
            if elem.get("key", "") == "pem":
                pem = (elem.text or "").replace("&#xa;", "\n")

        # 简单正则提取
        txt_dump = ET.tostring(script, encoding='unicode')
        m_ocsp = re.search(r"OCSP.*?URI:([^\s<]+)", txt_dump)
        if m_ocsp: ocsp_url = m_ocsp.group(1)
        m_iss = re.search(r"CA Issuers.*?URI:([^\s<]+)", txt_dump)
        if m_iss: issuer_url = m_iss.group(1)

        if pem: out.append({"ip": ip, "pem": pem, "ocsp": ocsp_url, "issuer": issuer_url})
    return out


def check_single_cert_ocsp(rec):
    if not rec.get("ocsp"): return {"status": "unknown", "note": "no_ocsp_url"}
    try:
        with tempfile.TemporaryDirectory() as td:
            leaf = os.path.join(td, "leaf.pem")
            with open(leaf, "w", encoding="utf-8") as f:
                f.write(rec["pem"])
            issuer_pem = os.path.join(td, "issuer.pem")

            if rec.get("issuer") and rec["issuer"].startswith("http"):
                try:
                    urllib.request.urlretrieve(rec["issuer"], issuer_pem)
                except:
                    return {"status": "error", "note": "issuer_dl_fail"}
            else:
                return {"status": "unknown", "note": "no_issuer_url"}

            if os.path.exists(issuer_pem):
                cmd = ["openssl", "ocsp", "-issuer", issuer_pem, "-cert", leaf, "-url", rec["ocsp"], "-resp_text",
                       "-noverify", "-timeout", "10"]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                out = (r.stdout + "\n" + r.stderr).lower()
                if "revoked" in out:
                    return {"status": "revoked", "note": "revoked"}
                elif "good" in out:
                    return {"status": "good", "note": "good"}
                else:
                    return {"status": "unknown", "note": "cmd_output_unknown"}
            return {"status": "unknown", "note": "issuer_pem_missing"}
    except Exception as e:
        return {"status": "error", "note": str(e)}


def ocsp_check_sample(xml_path, sample_n=100):
    if sample_n <= 0: return {"status_count": {}, "rows": [], "note": "skip"}
    if not detect_openssl(): return {"status_count": {}, "rows": [], "note": "openssl_not_found"}
    recs = parse_xml_extract_records(xml_path)
    if not recs: return {"status_count": {}, "rows": [], "note": "no_xml_records"}

    sample = random.sample(recs, min(sample_n, len(recs)))
    results = []
    print(f"⏳ Running OCSP check for {len(sample)} certs...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_map = {executor.submit(check_single_cert_ocsp, r): r for r in sample}
        for f in as_completed(future_map):
            r = future_map[f]
            res = f.result()
            results.append({"ip": r.get("ip"), "status": res["status"], "note": res["note"]})

    sc = {}
    for r in results: sc[r["status"]] = sc.get(r["status"], 0) + 1
    return {"status_count": sc, "rows": results, "note": "done"}


# =================绘图辅助=================

def _wrap_labels(labels, width=15):
    return ["\n".join(wrap(str(x), width=width)) for x in labels]


def save_bar_chart(pairs, title, xlabel, filename):
    if not HAS_MPL or not pairs: return False

    # 过滤无效数据
    pairs = [p for p in pairs if p[0] and str(p[0]).lower() not in ["nan", "none", "(空)"]]
    pairs = sorted(pairs, key=lambda kv: kv[1], reverse=True)
    if not pairs: return False

    labels = [str(k) for k, _ in pairs]
    values = [v for _, v in pairs]

    plt.figure(figsize=(10, 6))

    # [优化] 控制 bar 的最大宽度 width=0.6，zorder=3 让柱子在网格线上方
    bars = plt.bar(range(len(values)), values, color=BAR_COLORS[:len(values)],
                   width=0.6, alpha=0.9, edgecolor='white', zorder=3)

    for i, b in enumerate(bars):
        plt.text(b.get_x() + b.get_width() / 2, b.get_height() + (max(values) * 0.01),
                 f"{values[i]}", ha="center", va="bottom", fontsize=9, color="#444", fontweight='bold')

    plt.title(title, pad=15, fontweight="bold", fontsize=12)
    plt.xlabel(xlabel)
    plt.ylabel("Count")
    plt.xticks(range(len(values)), _wrap_labels(labels), rotation=0, ha="center")
    plt.grid(axis='y', linestyle='--', alpha=0.4, zorder=0)
    plt.tight_layout()

    plt.savefig(os.path.join(CHART_DIR, filename), bbox_inches="tight")
    plt.close()
    return True


def save_pie_chart(labels_counts, title, filename):
    if not HAS_MPL: return False
    data = [x for x in labels_counts if x[1] > 0]
    if not data: return False

    labels = [x[0] for x in data]
    sizes = [x[1] for x in data]

    plt.figure(figsize=(7, 7))
    plt.pie(sizes, labels=labels, autopct=lambda p: f'{p:.1f}%' if p > 2 else '',
            startangle=140, colors=PIE_COLORS,
            wedgeprops={'edgecolor': 'white', 'linewidth': 1.5})
    plt.title(title, pad=15, fontweight="bold")
    plt.tight_layout()
    plt.savefig(os.path.join(CHART_DIR, filename), bbox_inches="tight")
    plt.close()
    return True


# =================主逻辑=================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--xml", default=os.path.join("data", "raw", "final_certs.xml"))
    parser.add_argument("--extra", help="External CSV")
    parser.add_argument("--sample", type=int, default=0)
    parser.add_argument("--ext-cap", type=float, default=0.1)
    parser.add_argument("--charts-src", choices=["merged", "nmap", "balanced"], default="merged")
    args = parser.parse_args()

    print("🚀 Starting SSL Pipeline...")
    needed = ["IP", "Host", "Port", "Subject_CN", "Issuer_CN", "SAN", "Pubkey_Type", "Pubkey_Bits", "Sig_Algo",
              "NotBefore", "NotAfter", "Validity_Days", "Days_Remaining", "Fingerprint", "source"]

    # 1. 读取基础数据
    base_rows = ensure_columns(read_csv_rows(args.input_csv), needed)
    for r in base_rows: r.setdefault("source", "nmap")

    # 2. 合并外部数据
    merged_rows = base_rows
    if args.extra and os.path.exists(args.extra):
        extra_rows = ensure_columns(read_csv_rows(args.extra), needed)
        merged_rows = merge_and_dedupe(base_rows, extra_rows)
        print(f"✅ Merged {len(extra_rows)} external rows.")

    write_csv(os.path.join(LIST_DIR, "dataset_merged.csv"), merged_rows)

    # 3. 复用分析
    reuse_top = reuse_by_cert(merged_rows, topk=50)
    write_csv(os.path.join(LIST_DIR, "cert_reuse_top50.csv"), reuse_top)

    # 4. 准备绘图数据 (Balanced)
    nmap_rows = [r for r in merged_rows if r.get("source") == "nmap"]
    ext_rows = [r for r in merged_rows if r.get("source") != "nmap"]

    balanced_rows = list(nmap_rows)
    if ext_rows and args.ext_cap > 0:
        cap = int(len(nmap_rows) * args.ext_cap)
        balanced_rows += random.sample(ext_rows, min(cap, len(ext_rows)))
    write_csv(os.path.join(LIST_DIR, "dataset_merged_balanced.csv"), balanced_rows)

    # 5. 生成图表
    chart_rows = merged_rows
    if args.charts_src == "nmap":
        chart_rows = nmap_rows
    elif args.charts_src == "balanced":
        chart_rows = balanced_rows

    top_issuer = counter_topn(chart_rows, "Issuer_CN", 10)
    top_sig = counter_topn(chart_rows, "Sig_Algo", 10)
    top_keytype = counter_topn(chart_rows, "Pubkey_Type", 10)
    top_bits = counter_topn(chart_rows, "Pubkey_Bits", 10)
    ov = compute_overview(chart_rows)

    if HAS_MPL:
        save_bar_chart(top_issuer, "Top 10 Issuers", "Issuer Name", "chart_issuer_top10.png")
        save_bar_chart(top_sig, "Top 10 Signature Algorithms", "Algorithm", "chart_sig_algo_top10.png")
        save_bar_chart(top_keytype, "Top 10 Public Key Types", "Key Type", "chart_pubkey_type_top10.png")
        save_bar_chart(top_bits, "Top 10 Key Bits", "Bits", "chart_pubkey_bits_top10.png")

        ok = ov["total"] - ov["expired"] - ov["expiring_30"]
        save_pie_chart([("Valid", ok), ("Expiring (<=30d)", ov["expiring_30"]), ("Expired", ov["expired"])],
                       "Certificate Validity Status", "chart_expiry_pie.png")

    # 6. OCSP 检查
    ocsp_res = {"status_count": {}, "rows": [], "note": "not run"}
    if args.sample > 0:
        ocsp_res = ocsp_check_sample(args.xml, args.sample)
        write_csv(os.path.join(LIST_DIR, "revocation_sample_result.csv"), ocsp_res["rows"])

    # 7. 生成报告 (Strict Structure)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def fmt_top(lst):
        return "\n".join([f"- {k}：{v}" for k, v in lst]) if lst else "(No Data)"

    sc = ocsp_res["status_count"]
    total_ocsp = sum(sc.values()) if sc else 0

    def pct(x):
        return f"{(x / total_ocsp * 100):.1f}%" if total_ocsp else "0.0%"

    report = []
    report.append("# Analyzing SSL/TLS certificates used by real web sites\n")
    report.append(f"**Generated**: {now}\n")
    report.append("## Major steps:\n")

    report.append("### • Create a tool or use existing tool to scan 1K HTTPs web sites and collect their certificates.")
    report.append(f"- **Total Scanned Hosts (Nmap)**: {len(nmap_rows)}")
    report.append(f"- **Valid Certificates Parsed**: {len([r for r in nmap_rows if r.get('Subject_CN')])}\n")

    report.append("### • Use existing security search engine to collect more certificates.")
    report.append("- **External Source**: crt.sh (or similar)")
    report.append(f"- **External Records Added**: {len(merged_rows) - len(nmap_rows)}")
    report.append(f"- **Total Unique Certificates (Merged)**: {len(merged_rows)}\n")

    report.append("### • Analyze the hosts sending back the certificates")
    report.append("- **Certificate Reuse**: Analyzed via SHA-256 fingerprint.")
    if reuse_top:
        report.append(
            f"- **Top Shared Cert**: `{reuse_top[0]['Key'][:30]}...` (Used by **{reuse_top[0]['unique_IPs']}** IPs)")
    report.append("- Full list: `results/lists/cert_reuse_top50.csv`\n")

    report.append("### • Analyze the properties of certificates")
    report.append(f"> **Dataset used for charts**: {args.charts_src} (Total: {len(chart_rows)})")
    report.append("**Top Issuers**\n" + fmt_top(top_issuer) + "\n![](charts/chart_issuer_top10.png)\n")
    report.append("**Signature Algorithms**\n" + fmt_top(top_sig) + "\n![](charts/chart_sig_algo_top10.png)\n")
    report.append("**Public Key Types**\n" + fmt_top(top_keytype) + "\n![](charts/chart_pubkey_type_top10.png)\n")
    report.append("**Key Bits**\n" + fmt_top(top_bits) + "\n![](charts/chart_pubkey_bits_top10.png)\n")
    report.append("**Validity Status**\n![](charts/chart_expiry_pie.png)\n")

    report.append("### • Measure the certification revocation of web sites.")
    if total_ocsp > 0:
        report.append(f"- **Sample Size**: {total_ocsp}")
        report.append(f"- **Good**: {sc.get('good', 0)} ({pct(sc.get('good', 0))})")
        report.append(f"- **Revoked**: {sc.get('revoked', 0)} ({pct(sc.get('revoked', 0))})")
        report.append(
            f"- **Unknown/Error**: {sc.get('unknown', 0) + sc.get('error', 0)} ({pct(sc.get('unknown', 0) + sc.get('error', 0))})")
        report.append("- Raw results: `results/lists/revocation_sample_result.csv`\n")
    else:
        report.append("- OCSP check was skipped or failed in this run.\n")

    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(report))
    print(f"✅ Report generated at: {REPORT_MD}")


if __name__ == "__main__":
    main()