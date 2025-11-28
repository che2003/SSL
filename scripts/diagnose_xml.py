import xml.etree.ElementTree as ET
import os
import argparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_XML = os.path.join(BASE_DIR, "data", "raw", "scan_results.xml")


def diagnose_xml(xml_file):
    if not os.path.exists(xml_file):
        print(f"❌ 错误：找不到文件 '{xml_file}'")
        return

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"❌ XML 解析失败: {e}")
        return

    total_hosts = len(root.findall("host"))
    open_443 = 0
    with_cert = 0

    for host in root.findall("host"):
        port = host.find(".//port[@portid='443']")
        if port is None:
            continue

        state = port.find("state")
        if state is not None and state.get("state") == "open":
            open_443 += 1
            if port.find(".//script[@id='ssl-cert']") is not None:
                with_cert += 1

    print("\n--- XML 诊断报告 ---")
    print(f"文件路径: {xml_file}")
    print(f"1. 主机总数: {total_hosts}")
    print(f"2. 开放 443: {open_443}")
    print(f"3. 含证书数据: {with_cert}")

    if with_cert == 0:
        print("\n⚠️ 警告: 没有发现证书数据。请检查扫描命令是否包含 --script ssl-cert")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--xml", default=DEFAULT_XML, help="要诊断的 XML 文件路径")
    args = parser.parse_args()

    diagnose_xml(args.xml)
