import csv
import logging
from pathlib import Path
from requests import get, RequestException
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from defusedxml.ElementTree import parse
from cryptography import x509
from datetime import datetime

# 配置日志
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def fetch_revoked_keybox_list():
    try:
        session = get_session_with_retries()
        response = session.get(
            "https://android.googleapis.com/attestation/status",
            headers={
                "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
        response.raise_for_status()
        logging.info("Successfully fetched revoked keybox list.")
        return response.json()["entries"]
    except RequestException as e:
        logging.error(f"Failed to fetch revoked keybox list: {e}")
        raise

def get_session_with_retries():
    session = get()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session

def main():
    try:
        revoked_keybox_list = fetch_revoked_keybox_list()
    except Exception as e:
        logging.error(f"Exiting due to fetch error: {e}")
        return

    # 确保 status.csv 文件可以写入
    csv_path = Path("status.csv")
    if csv_path.exists():
        try:
            csv_path.unlink()  # 删除现有文件以防文件锁冲突
        except Exception as e:
            logging.error(f"Failed to delete existing CSV file: {e}")
            return

    with open(csv_path, "w", newline='') as csvfile:
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

        writer.writerows(output)
        
        # 写入时间戳
        writer.writerow({"File": "TIME", "Status": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        logging.info("CSV file has been successfully written.")

if __name__ == "__main__":
    main()
