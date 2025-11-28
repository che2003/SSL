import xml.etree.ElementTree as ET
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_XML = os.path.join(BASE_DIR, "data", "raw", "open443.xml")
OUTPUT_FILE = os.path.join(BASE_DIR, "data", "processed", "active_ips.txt")


def extract_ips(xml_file, output_file):
    if not os.path.exists(xml_file):
        print(f"❌ 错误：找不到文件 '{xml_file}'")
        print("   请先运行 Nmap 端口扫描并将结果保存到 data/raw/ 目录。")
        return

    active_ips = set()
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"❌ XML 解析失败: {e}")
        return

    for host in root.findall("host"):
        ip_addr = None
        addr_tag = host.find("address")
        if addr_tag is not None:
            ip_addr = addr_tag.get("addr")

        if not ip_addr:
            continue

        port_element = host.find(".//port[@portid='443']")
        if port_element is None:
            continue

        state_tag = port_element.find("state")
        if state_tag is not None and state_tag.get("state") == "open":
            active_ips.add(ip_addr)

    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as outfile:
        outfile.write("\n".join(active_ips))

    print(f"✅ 提取完成：找到 {len(active_ips)} 个活跃 IP。")
    print(f"📄 输出文件：{output_file}")


if __name__ == "__main__":
    print("--- 提取活跃 IP ---")
    extract_ips(INPUT_XML, OUTPUT_FILE)
