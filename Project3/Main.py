import os
import subprocess
import requests
import json
import pefile
from datetime import datetime

VT_API_KEY = "e53e81b24153982866efee42bdd3014d7516e6958c3d0626aee19e7e9b292d19"

STRINGS_PATH = "Strings\\strings.exe"
def run_strings(file, out_folder):
    print("[+] Running strings...")
    output_file = os.path.join(out_folder, "strings.txt")

    result = subprocess.run(
        [STRINGS_PATH, file],
        capture_output=True,
        text=True
    )

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(result.stdout)

    print("    -> Saved to strings.txt")

DIEC_PATH = "die_win64_portable_3.10_x64\\diec.exe"
def run_detect_it_easy(file, out_folder):
    print("[+] Running Detect It Easy (DIE)...")
    output_file = os.path.join(out_folder, "die.json")

    result = subprocess.run(
        [DIEC_PATH, "-j", file], 
        capture_output=True,
        text=True
    )

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(result.stdout)

    print("    -> Saved to die.json")


def analyze_pe_headers(file, out_folder):
    print("[+] Extracting PE header information...")

    try:
        pe = pefile.PE(file)
    except:
        print("[-] Not a PE file")
        return

    info = {
        "EntryPoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "ImageBase": hex(pe.OPTIONAL_HEADER.ImageBase),
        "Sections": [],
    }

    for section in pe.sections:
        info["Sections"].append({
            "Name": section.Name.decode(errors="ignore").strip("\x00"),
            "VirtualAddress": hex(section.VirtualAddress),
            "SizeOfRawData": section.SizeOfRawData,
            "Entropy": section.get_entropy(),
        })

    output_file = os.path.join(out_folder, "pe_info.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=4)

    print("    -> Saved to pe_info.json")


def get_file_metadata(file, out_folder):
    print("[+] Extracting file metadata...")
    stat_info = os.stat(file)

    metadata = {
        "File": os.path.basename(file),
        "Size (bytes)": stat_info.st_size,
        "Modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
        "Created": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
    }

    output_file = os.path.join(out_folder, "metadata.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)

    print("    -> Saved to metadata.json")


def vt_upload(file):
    print("[+] Uploading file to VirusTotal...")
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}

    with open(file, "rb") as f:
        files = {"file": f}
        r = requests.post(url, files=files, headers=headers)

    return r.json()["data"]["id"]


def vt_get_report(analysis_id, out_folder):
    print("[+] Getting VirusTotal report...")
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}

    r = requests.get(url, headers=headers)
    output_file = os.path.join(out_folder, "virustotal_report.json")

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(r.json(), f, indent=4)

    print("    -> Saved to virustotal_report.json")


def static_analysis(file):
    print(f"[START] Static analysis for {file}")

    out_folder = os.path.splitext(file)[0] + "_analysis"
    os.makedirs(out_folder, exist_ok=True)

    get_file_metadata(file, out_folder)
    analyze_pe_headers(file, out_folder)
    run_strings(file, out_folder)
    run_detect_it_easy(file, out_folder)

    try:
        analysis_id = vt_upload(file)
        vt_get_report(analysis_id, out_folder)
    except Exception as e:
        print("[-] VirusTotal error:", e)

    print(f"\n[SUCCESS] Analysis complete! Saved in folder: {out_folder}\n")


if __name__ == "__main__":
    target = input("Enter path to malware file: ").strip()
    static_analysis(target)
