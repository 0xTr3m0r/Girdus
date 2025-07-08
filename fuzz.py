import requests
import sys
import json








def fuzz_endpoints(url, filename, method="get", data=None, headers=None, status=200):
    method = method.lower()
    data = data or {}
    headers = headers or {}
    found_endpoints = []

    try:
        with open(filename, 'r') as f:
            payloads = [line.strip() for line in f.readlines()]
    except Exception as e:
        print(f"[!] Error reading payload file: {e}")
        return []

    if "FUZZ" in url:
        print("[*] Starting path fuzzing...")
        for payload in payloads:
            full_url = url.replace("FUZZ", payload)
            try:
                response = requests.request(method.upper(), full_url, headers=headers, data=data)
                if response.status_code == status:
                    found_endpoints.append(full_url)
                    print(f"[+] Found endpoint: {full_url}")
                else:
                    continue
            except requests.RequestException as e:
                print(f"[!] Request failed for {full_url}: {e}")
                continue

    elif "FUZZ" in json.dumps(data):
        print("[*] Starting JSON body fuzzing...")
        if method not in ["post", "put", "patch", "delete"]:
            print("[!] JSON fuzzing requires a body-supporting HTTP method.")
            return []

        for payload in payloads:
            fuzzed_data = {
                k: v.replace("FUZZ", payload) if isinstance(v, str) else v
                for k, v in data.items()
            }
            try:
                response = requests.request(
                    method.upper(),
                    url,
                    headers=headers,
                    json=fuzzed_data 
                )
                if response.status_code == status:
                    found_endpoints.append(fuzzed_data)
                    print(f"[+] Valid JSON payload: {json.dumps(fuzzed_data)}")
                else:
                    continue
            except requests.RequestException as e:
                print(f"[!] Request failed for JSON payload: {e}")
                continue

    else:
        print("[!] No FUZZ keyword found in URL or data. Nothing to fuzz.")
    
    return found_endpoints

    
    
import argparse
import json

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
        status=args.status
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
