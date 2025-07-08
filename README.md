# 🔍 Fuzzer: Endpoint & JSON Payload Fuzzer

> A basic multithreaded fuzzing tool built in Python — designed for **learning offensive security** and improving **Python skills**.

---

## 🚀 Features

-  Path-based fuzzing via `FUZZ` keyword in URL
-  JSON body fuzzing (replace `FUZZ` in data fields)
-  Support for custom headers (`-H`) and data (`-D`)
-  Multithreaded with `concurrent.futures`
-  Progress bar using `tqdm`
-  Filter by HTTP status code (default: 200)
-  Save found results to file (`-o`)

---

## 📚 Learning Goals

This tool was created as a **learning project** to:

- Practice Python scripting in a security context
- Understand how fuzzing works (paths, payloads, JSON)
- Learn to use:
  - `requests`
  - `argparse`
  - `json`
  - `ThreadPoolExecutor`
  - `tqdm`

---

## 🛠️ Usage

### ⚙️ Basic Path Fuzzing

```bash
python fuzz.py -u "https://example.com/FUZZ" -w wordlist.txt
```
### 🧪 JSON Body Fuzzing

```bash
python fuzz.py -u "https://example.com/api" -X POST \
  -w payloads.txt \
  -H "{\"Content-Type\": \"application/json\"}" \
  -D "{\"username\": \"FUZZ\"}
```
### 🧪 JSON Body Fuzzing

```bash
python fuzz.py -u "https://target.com/FUZZ" -w paths.txt -o results.txt

```
