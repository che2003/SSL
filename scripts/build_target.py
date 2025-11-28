import csv
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_FILENAME = os.path.join(BASE_DIR, "data", "raw", "top-1m.csv")
OUTPUT_FILENAME = os.path.join(BASE_DIR, "data", "processed", "targets.txt")

NUM_TARGETS = 3000


def main():
    if not os.path.exists(INPUT_FILENAME):
        print(f"❌ 错误：找不到输入文件 '{INPUT_FILENAME}'")
        print("   请确保你已将 'top-1m.csv' 放入 'data/raw/' 文件夹中。")
        return

    try:
        os.makedirs(os.path.dirname(OUTPUT_FILENAME), exist_ok=True)

        with open(INPUT_FILENAME, "r", encoding="utf-8") as infile:
            reader = csv.reader(infile)
            targets = []
            count = 0

            for row in reader:
                if count >= NUM_TARGETS:
                    break
                if len(row) > 1:
                    domain = row[1].strip()
                    if domain:
                        targets.append(domain)
                        count += 1

        with open(OUTPUT_FILENAME, "w", encoding="utf-8") as outfile:
            outfile.write("\n".join(targets))

        print(f"✅ 成功提取前 {count} 个域名。")
        print(f"📄 输出文件：{OUTPUT_FILENAME}")

    except Exception as e:
        print(f"❌ 发生错误: {e}")


if __name__ == "__main__":
    main()
