import csv
import logging
import os
from pathlib import Path
from requests import get, RequestException
from defusedxml.ElementTree import parse
from cryptography import x509
from datetime import datetime, timedelta

# 配置日志
logging.basicConfig(level=logging.INFO)

def fetch_revoked_keybox_list():
    try:
        response = get(
            "https://android.googleapis.com/attestation/status",
            headers={
                "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
        response.raise_for_status()  # Raise an error for bad responses
        return response.json()["entries"]
    except RequestException as e:
        logging.error(f"Failed to fetch revoked keybox list: {e}")
        raise

def main():
    # 确认当前工作目录
    logging.info(f"Current working directory: {os.getcwd()}")

    revoked_keybox_list = fetch_revoked_keybox_list()

    # 使用绝对路径创建 CSV 文件
    output_path = Path("status.csv").resolve()
    logging.info(f"Output path for CSV: {output_path}")

    with open(output_path, "w", newline='') as csvfile:
        fieldnames = ["File", "Status"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        output = []

        for kb in Path(".").glob("*.xml"):
            try:
                values = {}
                values["File"] = kb.name

                root = parse(kb).getroot()
                pem_number = int(root.find(".//NumberOfCertificates").text.strip())
                pem_certificates = [
                    cert.text.strip()
                    for cert in root.findall('.//Certificate[@format="pem"]')[:pem_number]
                ]
                certificate = x509.load_pem_x509_certificate(pem_certificates[0].encode())
                serial_number = hex(certificate.serial_number)[2:]

                # 检查吊销状态
                if serial_number not in revoked_keybox_list:
                    values["Status"] = "✅"
                    output.append(values)  # 只添加未吊销的条目
                else:
                    logging.info(f"{values['File']} is revoked.")

            except Exception as e:
                logging.error(f"Error processing {kb.name}: {e}")

        logging.info(f"Output data: {output}")
        writer.writerows(output)
        
        # 写入时间戳，增加3小时
        new_time = datetime.now() + timedelta(hours=8)
        writer.writerow({"File": "TIME", "Status": new_time.strftime("%Y-%m-%d %H:%M:%S")})

if __name__ == "__main__":
    main()
