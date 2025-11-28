# SSL/TLS Measurement Report

Generated: 2025-11-21 20:42:41

## 1. Data Sources and Processing

- Nmap-only (scan-derived): 1167 rows, unique IPs 1167, unique Subject_CN 1000.
- External data provided: 3333 rows; cap = 0.30; included after capping: 350 rows.
- Merged datasets: **balanced** 1383 rows; **full** 4366 rows (dedup-only).

> Charts default to the balanced dataset (nmap + capped external) to avoid bias from historical CT entries.

## 2. Certificate Property Distributions
### 2.1 Nmap-only (live deployment view)

**Issuer Top 10**
- DigiCert Global G2 TLS RSA SHA256 2020 CA1: 109
- WE1: 66
- GlobalSign RSA OV SSL CA 2018: 61
- R12: 56
- R13: 52
- Sectigo RSA Domain Validation Secure Server CA: 44
- E7: 40
- Amazon RSA 2048 M02: 39
- Amazon RSA 2048 M04: 39
- Amazon RSA 2048 M03: 36

![](chart_issuer_nmap.png)

**Signature Algorithm Top 10**
- sha256WithRSAEncryption: 927
- ecdsa-with-SHA384: 111
- ecdsa-with-SHA256: 83
- sha384WithRSAEncryption: 43
- sha512WithRSAEncryption: 3

![](chart_sig_nmap.png)

**Public Key Type Top 10**
- rsa: 932
- ec: 235

![](chart_ktype_nmap.png)

**Public Key Bits Top 10**
- 2048: 863
- 256: 231
- 4096: 69
- 384: 4

![](chart_bits_nmap.png)


### 2.2 Balanced Merged

**Issuer Top 10**
- DigiCert Global G2 TLS RSA SHA256 2020 CA1: 101
- WE1: 63
- GlobalSign RSA OV SSL CA 2018: 58
- R13: 52
- C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance CA-3: 48
- R12: 43
- Sectigo RSA Domain Validation Secure Server CA: 39
- Amazon RSA 2048 M04: 39
- Amazon RSA 2048 M02: 38
- C=US, O="Thawte, Inc.", CN=Thawte SSL CA: 37

![](chart_issuer_bal.png)

**Signature Algorithm Top 10**
- sha256WithRSAEncryption: 841
- (empty): 350
- ecdsa-with-SHA256: 79
- ecdsa-with-SHA384: 77
- sha384WithRSAEncryption: 34
- sha512WithRSAEncryption: 2

![](chart_sig_bal.png)

**Public Key Type Top 10**
- rsa: 848
- (empty): 350
- ec: 185

![](chart_ktype_bal.png)

**Public Key Bits Top 10**
- 2048: 780
- (empty): 350
- 256: 181
- 4096: 68
- 384: 4

![](chart_bits_bal.png)

## 3. Expiry and Lists (balanced)

- Expired: 50 (3.6%)
- <=30 days: 101 (7.3%)

Details exported: `list_expired.csv` and `list_expiring_30d.csv`.

![](chart_expiry_bal.png)

![](chart_days_bal.png)

## 4. Certificate Reuse (by fingerprint)

- Top1 key: `18fece093913d57220eb6bb139187659c4bf52f28dfa39b570bafe11187e7828`  unique IPs = **1**
See `cert_reuse_top50.csv`.

## 5. Revocation Measurement (OCSP sampling)

- Sampling: 100  
- Results: good=77 (77.0%), revoked=0 (0.0%), unknown=19 (19.0%), error=4 (4.0%)
Details: `revocation_sample_result.csv`.

## 6. Reproducibility

1) Nmap collection:
```bash
nmap -Pn -n -p 443 --open -iL active_ips.txt -T4 -oX open443.xml
nmap -Pn -n -p 443 --script ssl-cert -iL open443.txt -T4 -oX final_certs.xml
```
2) XML → CSV: `analyze_certs.py` (this version writes the `Fingerprint` column).
3) Pipeline:
```bash
python ssl_pipeline.py --input-csv data/processed/certificate_analysis.csv --xml data/raw/final_certs.xml --extra data/processed/extra_from_search.csv --ext-cap 0.3 --sample 100
```