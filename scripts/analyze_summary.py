import pandas as pd
from datetime import datetime, timedelta

CSV = "certificate_analysis.csv"


def main():
    df = pd.read_csv(CSV)

    for need in [
        "IP",
        "Subject_CN",
        "Issuer_CN",
        "Pubkey_Type",
        "Pubkey_Bits",
        "Sig_Algo",
        "NotBefore",
        "NotAfter",
        "Validity_Days",
        "Days_Remaining",
        "SAN",
        "Host",
        "Port",
    ]:
        if need not in df.columns:
            df[need] = ""

    now = datetime.now()

    total = len(df)
    unique_ips = df["IP"].nunique()
    unique_subjects = df["Subject_CN"].nunique()
    print(f"总证书记录: {total}, 覆盖IP: {unique_ips}, 不同Subject_CN: {unique_subjects}")

    df["Days_Remaining"] = pd.to_numeric(df["Days_Remaining"], errors="coerce")
    expired = df[df["Days_Remaining"] < 0]
    expiring_30 = df[(df["Days_Remaining"] >= 0) & (df["Days_Remaining"] <= 30)]
    print(f"已过期: {len(expired)}  ({len(expired) / max(total, 1):.1%})")
    print(f"<=30天到期: {len(expiring_30)}  ({len(expiring_30) / max(total, 1):.1%})")

    for col, topn in [("Issuer_CN", 10), ("Sig_Algo", 10), ("Pubkey_Type", 10), ("Pubkey_Bits", 10)]:
        print(f"\nTop {topn} {col}:")
        print(df[col].value_counts().head(topn))

    expired.to_csv("list_expired.csv", index=False)
    expiring_30.to_csv("list_expiring_30d.csv", index=False)
    print("\n已导出：list_expired.csv / list_expiring_30d.csv")


if __name__ == "__main__":
    main()
