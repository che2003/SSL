
# SSL 证书测量与分析流水线

这个项目是一条 **从互联网目标选择 → Nmap 扫描 → 证书解析 → 统计分析 → Markdown 报告** 的自动化流水线，主要用于课程作业或小规模互联网测量实验。

---

## 1. 目录结构

以项目根目录 `SSL/` 为例：

```text
SSL/
├── data/
│   ├── raw/                # 原始输入数据（Top 列表、Nmap XML）
│   │   ├── top-1m.csv
│   │   ├── scan_results.xml
│   │   ├── open_443_ips.xml
│   │   └── final_certs.xml
│   └── processed/          # 处理后的中间结果
│       ├── targets.txt
│       ├── active_ips.txt
│       └── certificate_analysis.csv
├── results/
│   ├── charts/             # Matplotlib 生成的图表
│   └── lists/              # 各种明细列表
│       ├── list_expired.csv
│       ├── list_expiring_30d.csv
│       ├── cert_reuse_top50.csv
│       └── revocation_sample_result.csv (可选，OCSP 抽样)
│   └── REPORT.md           # 最终 Markdown 报告
└── scripts/
    ├── build_target.py
    ├── extract_active_ips.py
    ├── diagnose_xml.py
    ├── analyze_certs.py
    ├── analyze_summary.py  # 旧版简单分析脚本（可选）
    └── ssl_pipeline.py     # 新版总控+汇总站脚本
```

> 所有脚本默认都假设自己位于 `scripts/` 目录，路径通过 `BASE_DIR = 项目根目录` 自动计算，请从项目根目录执行 `python scripts/xxx.py`。

---

## 2. 环境与依赖

- Python 3.8+
- Nmap（命令行工具）
- Python 依赖：
  - 标准库：`csv`, `os`, `argparse`, `datetime`, `xml.etree.ElementTree`, `re` 等
  - 可选：`matplotlib`（用于生成图表）

安装 `matplotlib`：

```bash
pip install matplotlib
```

---

## 3. 使用流程（一步步跑通）

### Step 0：准备目标列表与目录

1. 将你的域名排名列表放到 `data/raw/top-1m.csv`  
   （格式至少要包含一列域名；脚本默认读取前 3000 个）。
2. 确保 `data/raw/`、`data/processed/`、`results/` 等目录存在（脚本会自动创建缺失的子目录）。

---

### Step 1：构建扫描目标列表

```bash
cd SSL
python scripts/build_target.py
```

作用：

- 从 `data/raw/top-1m.csv` 中提取前 N（默认 3000）个域名
- 写入 `data/processed/targets.txt`，每行一个域名

---

### Step 2：Nmap 扫描 443 端口 & 简单诊断（可选）

1. 使用 `targets.txt` 扫描 443 端口是否开放，并保存原始 XML：

   ```bash
   nmap -T4 --host-timeout 5m -iL data/processed/targets.txt \
        -p 443 --open -oX data/raw/scan_results.xml
   ```

2. 使用脚本做一个快速诊断，确认扫描结果合理：

   ```bash
   python scripts/diagnose_xml.py --xml data/raw/scan_results.xml
   ```

   输出包括：

   - 主机总数
   - 开放 443 的主机数
   - 含证书数据的主机数（用于检查是否加了 `--script ssl-cert`）

---

### Step 3：提取开放 443 的活跃 IP

```bash
python scripts/extract_active_ips.py
```

- 从 `data/raw/open_443_ips.xml` 中抽取 443 端口 `state=open` 的 IP
- 生成 `data/processed/active_ips.txt`（每行一个 IP）

> 如果你在 Step 2 直接把扫描结果保存为 `open_443_ips.xml`，脚本可以直接使用；否则可以修改脚本顶部的 `INPUT_XML` 路径。

---

### Step 4：对活跃 IP 进行证书扫描

使用 `active_ips.txt` 再跑一次带 `ssl-cert` 的 Nmap：

```bash
nmap -T4 --host-timeout 5m -iL data/processed/active_ips.txt \
     -p 443 -sV -n --script=ssl-cert \
     -oX data/raw/final_certs.xml
```

- `final_certs.xml` 就是后续证书解析的主要输入。

---

### Step 5：解析证书 XML → CSV

```bash
python scripts/analyze_certs.py
```

- 从 `data/raw/final_certs.xml` 中解析出：
  - IP、Host、Subject_CN、Issuer_CN
  - SAN、公钥类型/位数、签名算法
  - NotBefore / NotAfter、有效期天数、剩余天数等
- 生成 `data/processed/certificate_analysis.csv`

---

### Step 6：生成完整分析报告（推荐）

```bash
python scripts/ssl_pipeline.py
```

功能：

1. 读取 `certificate_analysis.csv`，计算总体概览：
   - 证书总数、唯一 IP 数、唯一 Subject_CN 数
   - 已过期证书数量及占比
   - 30 天内到期证书数量及占比

2. 生成统计明细：
   - 已过期证书列表：`results/lists/list_expired.csv`
   - 将在 30 天内到期的证书列表：`results/lists/list_expiring_30d.csv`
   - 证书复用 Top 50：`results/lists/cert_reuse_top50.csv`

3. 统计分布 & TopN：
   - Issuer（CA）Top10
   - 签名算法 `Sig_Algo` Top10
   - 公钥类型 `Pubkey_Type` Top10
   - 公钥长度 `Pubkey_Bits` Top10（密钥长度分布）

4. 图表（如安装了 `matplotlib`）：
   - CA 分布柱状图
   - 公钥类型分布柱状图
   - 签名算法分布柱状图
   - 密钥长度分布柱状图
   - 证书有效期状态饼图  
   图表统一输出到 `results/charts/` 并在报告中通过 `![...]` 引用。

5. 生成最终报告：

   - 输出文件：`results/REPORT.md`
   - 内容包括：
     - 数据概览
     - 证书有效期与到期风险
     - CA / 公钥类型 / 签名算法 / 密钥长度分布
     - 证书复用分析
     - （如有）OCSP 抽样吊销检查结果
     - 流水线方法论（便于复现）

> 旧脚本 `analyze_summary.py` 是早期的简单版本，只做基础统计并打印到终端，保留作参考，不再推荐使用。

---

## 4. 常见问题

### 4.1 没有生成图表怎么办？

- 检查是否安装了 `matplotlib`
- 或者脚本运行时是否报错：`Matplotlib missing, skipping charts.`  
  解决方案：`pip install matplotlib` 之后重新运行 `python scripts/ssl_pipeline.py`。

### 4.2 REPORT.md 里只有统计、没有“原始行数据”？

- 设计上 REPORT.md 是一个 **摘要报告**。
- 每条证书的详细字段请查看：
  - `data/processed/certificate_analysis.csv`
  - `results/lists/list_expired.csv`
  - `results/lists/list_expiring_30d.csv`
  - `results/lists/cert_reuse_top50.csv`

---

## 5. 免责声明

本项目仅用于教学与研究目的，不鼓励对未授权目标进行大规模扫描。请在遵守当地法律法规、学校/单位政策以及目标站点的使用条款前提下使用本工具链。
