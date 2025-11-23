import os
import hashlib

SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.cmd', '.vbs', '.scr', '.js', '.apk']
SUSPICIOUS_KEYWORDS = ['malware', 'trojan', 'rat', 'keylogger', 'hack', 'suspicious']

SIGNATURES = {
    "e99a18c428cb38d5f260853678922e03": "Test-Malware-1",
    "5d41402abc4b2a76b9719d911017c592": "Test-Malware-2"
}

def calculate_hash(file_path):
    sha1 = hashlib.sha1()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sha1.update(chunk)
        return sha1.hexdigest()
    except:
        return None


def scan_file(file_path):
    report = []

    ext = os.path.splitext(file_path)[1].lower()
    if ext in SUSPICIOUS_EXTENSIONS:
        report.append(f"Suspicious extension detected: {ext}")

    file_hash = calculate_hash(file_path)
    if file_hash and file_hash in SIGNATURES:
        report.append(f"Malware signature match found: {SIGNATURES[file_hash]}")

    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read().lower()
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in content:
                    report.append(f"Suspicious keyword found: {keyword}")
    except:
        report.append("Could not read file content (Skipped).")

    if not report:
        report.append("No threats detected.")

    return report


def main():
    folder = input("Enter folder path to scan: ")

    if not os.path.isdir(folder):
        print("Invalid folder path.")
        return

    for root, dirs, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"\nScanning: {file_path}")
            result = scan_file(file_path)
            for r in result:
                print(" -", r)


if __name__ == "__main__":
    main()
