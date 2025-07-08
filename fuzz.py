import requests
import sys

"""  

-first ferature to be improved : - recursive check for the found endpoints 
                                 - Improve handling errors 
                                 - Handle json data (to send it ) -D
                                 - Add Headers sending -H

"""
def fuzz_endpoints(url, filename, method="GET"):
    payloads = []
    found_endpoints = []

    try:
        with open(filename, 'r') as f:
            payloads = f.readlines()

        for payload in payloads:
            full_url = url.replace("FUZZ",payload.strip().lstrip('/'))
            try:
                response = requests.request(method.upper(), full_url)
                if response.status_code == 200:
                    found_endpoints.append(full_url)
                    print(f"[+] Found endpoint: {full_url}")
                else:
                    print(f"[-] {full_url} --> {response.status_code}")
            except requests.RequestException as e:
                print(f"[!] Request failed for {full_url}: {e}")
                continue

    except Exception as e:
        print(f"[!] Error reading payload file: {e}")

    return found_endpoints

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

    if len(sys.argv) <4:
        print("Usage:\n  python script.py -fuzz <url> <wordlist> <method>")
        sys.exit(1)

    if sys.argv[1] == "-fuzz":
        url = sys.argv[2]
        filename = sys.argv[3]
        method = sys.argv[4] if len(sys.argv) > 4 else "GET"
        found = fuzz_endpoints(url, filename, method)
        if found:
            print("\n[✓] Discovered Endpoints:")
            for f in found:
                print(f" - {f}")
        else:
            print("\n[✗] No valid endpoints found.")


if __name__ == "__main__":
    main()
