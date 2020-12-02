import requests
import os
import time
import argparse
from sensitive import api_key


def scan_file(f_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    files = {'file': (f_path, open(f_path, 'rb'))}
    response = requests.post(url, files=files, params=params)
    resource_id = response.json()["resource"]
    return resource_id


def generate_scan_report(resource_id):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key}
    local_params = {'resource': resource_id}
    full_params = dict()
    full_params.update(params)
    full_params.update(local_params)
    with requests.Session() as _sess:
        response = _sess.get(url, params=full_params)
    scan_data = {}
    if response.status_code == 200:
        for key, val in response.json().items():
            if key in ["scans", "verbose_msg", "total", "positives", "permalink", "scan_date"]:
                scan_data[key] = val
    return scan_data


def format_output(file_path, scan_data, detailed):
    print("Displaying VirusTotal scan results for file: %s" % file_path)
    try:
        if detailed:
            for vendor, res in scan_data["scans"].items():
                print("Vendor %s scan result: %s" % (vendor, res["detected"]))
        print("Vendor scan results: %s/%s" % (scan_data["positives"], scan_data["total"]))
        print("Scan verbose message: %s" % scan_data["verbose_msg"])
        print("Scan permalink: %s" % scan_data["permalink"])
    except Exception:
        print("Could not retrieve scan results from api, perhaps exceeded the rate limit")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan files with VirusTotal")
    parser.add_argument("--file", help="paths to files for scan", action="append")
    parser.add_argument("--dir", help="path to directory of files to scan", type=str)
    parser.add_argument("--detailed", help="show detailed scan results", action="store_true")
    args = parser.parse_args()
    fpaths = []
    if args.dir:
        fpaths = [args.dir + '\\' + fpath for fpath in os.listdir(args.dir)]
    if args.file:
        fpaths = args.file
    if not(args.file or args.dir) or (args.file and args.dir):
        print("Please provide correct input")
        os._exit(1)
    for fpath in fpaths:
        resource1 = scan_file(fpath)
        scan_res = generate_scan_report(resource_id=resource1)
        format_output(fpath, scan_res, args.detailed)
        time.sleep(30)
