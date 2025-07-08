import requests
import sys
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm



def single_fuzz_attempt(url, method, headers, data, payload, status, fuzz_type):
    try:
        if fuzz_type == "url":
            full_url = url.replace("FUZZ", payload)
            response = requests.request(method.upper(), full_url, headers=headers, data=data)
            if response.status_code == status:
                return full_url
        elif fuzz_type == "json":
            fuzzed_data = {
                k: v.replace("FUZZ", payload) if isinstance(v, str) else v
                for k, v in data.items()
            }
            response = requests.request(method.upper(), url, headers=headers, json=fuzzed_data)
            if response.status_code == status:
                return fuzzed_data
    except Exception as e:
        print(f"[!] Error during fuzz with payload '{payload}': {e}")
    return None


def fuzz_endpoints(url, filename, method="get", data=None, headers=None, status=200, output=None, threads=10):
    method = method.lower()
    data = data or {}
    headers = headers or {}
    found = []
    output = output or ''
    
    try:
        with open(filename, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]
    except Exception as e:
        print(f"[!] Error reading payload file: {e}")
        return []

    if "FUZZ" in url:
        fuzz_type = "url"
        print("[*] Starting path fuzzing...")
    elif "FUZZ" in json.dumps(data):
        fuzz_type = "json"
        print("[*] Starting JSON fuzzing...")
        if method not in ["post", "put", "patch", "delete"]:
            print("[!] JSON fuzzing requires a writeable method.")
            return []
    else:
        print("[!] No FUZZ found.")
        return []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(
                single_fuzz_attempt, url, method, headers, data, payload, status, fuzz_type
            ) for payload in payloads
        ]

        for future in tqdm(as_completed(futures), total=len(futures), desc="Fuzzing", unit="req"):
            result = future.result()
            if result:
                found.append(result)
                print(f"[+] Found: {result}")

    if output:
        try:
            with open(output, 'w') as f:
                for item in found:
                    f.write(f"{item}\n")
        except IOError as e:
            print(f"[!] Error writing to output file: {e}")

    return found
    
    


def main():
    print(r"""
   _______          __         
  / ____(_)        / _|        
 | |  __ _ _ __ __| |_   _ ___ 
 | | |_ | | '__/ _` | | | / __|
 | |__| | | | | (_| | |_| \__ \
  \_____|_|_|  \__,_|\__,_|___/
                               
       --==[ Fuzzer ]==--
       :: by 0xTr3m0r ::
""")

    parser = argparse.ArgumentParser(description="Basic Fuzzer for endpoints and JSON payloads")

    parser.add_argument("-u", "--url", required=True, help="Target URL with FUZZ keyword")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file path")
    
    parser.add_argument("-X", "--method", default="get", help="HTTP method (GET, POST, etc.)")
    parser.add_argument("-H", "--headers", help="Headers as JSON string")
    parser.add_argument("-D", "--data", help="Data (JSON body) as JSON string")
    parser.add_argument("-s", "--status", type=int, default=200, help="Expected status code (default: 200)")
    parser.add_argument("-o","--output",type=str,default='',help="File to save results")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use")

    args = parser.parse_args()

    try:
        headers = json.loads(args.headers) if args.headers else {}
    except Exception as e:
        print(f"[!] Failed to parse headers: {e}")
        headers = {}

    try:
        data = json.loads(args.data) if args.data else {}
    except Exception as e:
        print(f"[!] Failed to parse JSON data: {e}")
        data = {}

    results = fuzz_endpoints(
        url=args.url,
        filename=args.wordlist,
        method=args.method,
        data=data,
        headers=headers,
        status=args.status,
        output=args.output,
        threads=args.threads

    )

    print("\n[✓] Fuzzing complete.")
    if results:
        print("Found:")
        for r in results:
            print(f" - {r}")
    else:
        print("[✗] No valid results found.")


if __name__ == "__main__":
    main()
