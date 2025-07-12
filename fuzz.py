
import requests
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from typing import List, Optional, Union

def single_fuzz_attempt(
    url: str,
    method: str,
    headers: dict,
    data: dict,
    payload: str,
    status: int,
    fuzz_type: str
) -> Union[str, dict, None]:
    """
    Perform a single fuzzing attempt, either on the URL or JSON data.
    """
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

def subdomain_enum(domain: str, subdomains: List[str], threads: int = 10) -> List[str]:
    """
    Enumerate subdomains using multithreading.
    """
    found_subs = []
    def single_subdomain_enum(domain: str, subdomain: str, status: int = 200) -> Optional[str]:
        try:
            full_url = f"http://{subdomain}.{domain}"
            r = requests.get(full_url)
            if r.status_code == status:
                return full_url
        except requests.RequestException:
            pass
        return None
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(single_subdomain_enum, domain, subdomain) for subdomain in subdomains]
        for future in tqdm(as_completed(futures), total=len(futures), desc="Enumerating Subdomains", unit="sub"):
            result = future.result()
            if result:
                found_subs.append(result)
                print(f"[+] Found: {result}")
    return found_subs

def fuzz_endpoints(
    url: str,
    filename: str,
    method: str = "get",
    data: Optional[dict] = None,
    headers: Optional[dict] = None,
    status: int = 200,
    output: Optional[str] = None,
    threads: int = 10
) -> List[Union[str, dict]]:
    """
    Fuzz endpoints by replacing FUZZ in URL or JSON data with payloads from a file.
    """
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
        save_results(found, output)

    return found


def save_results(results: list, output_file: str) -> None:
    """
    Save results to a file, one per line.
    """
    try:
        with open(output_file, 'w') as f:
            for item in results:
                f.write(f"{item}\n")
    except IOError as e:
        print(f"[!] Error writing to output file: {e}")


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
    parser.add_argument("-u", "--url", help="Target URL with FUZZ keyword")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file path")
    parser.add_argument("-X", "--method", default="get", help="HTTP method (GET, POST, etc.)")
    parser.add_argument("-H", "--headers", help="Headers as JSON string")
    parser.add_argument("-D", "--data", help="Data (JSON body) as JSON string")
    parser.add_argument("-s", "--status", type=int, default=200, help="Expected status code (default: 200)")
    parser.add_argument("-o","--output",type=str,default='',help="File to save results")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use")
    parser.add_argument("-p","--proxy",default="127.0.0.1:8080",help="Add burpsuite proxy")
    parser.add_argument("-d","--domain",help="Domain for subdomain enumeration")
    args = parser.parse_args()

    # Custom argument validation: require either --url or --domain
    if not args.url and not args.domain:
        parser.error("You must provide either --url for fuzzing or --domain for subdomain enumeration.")
    if args.url and args.domain:
        parser.error("Please provide only one of --url or --domain, not both.")

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
    if args.domain:
        print("[*] Starting subdomain enumeration...")
        subdomains = []
        with open(args.wordlist, 'r') as f:
            subdomains = [line.strip() for line in f.readlines()]
        found_subs = subdomain_enum(args.domain, subdomains, threads=args.threads)
        if found_subs:
            print("[+] Found subdomains:")
            for sub in found_subs:
                print(f" - {sub}")
        else:
            print("[✗] No subdomains found.")
        return
    
    
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
