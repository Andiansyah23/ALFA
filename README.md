---

ALFA (Access & Logic Flaw Analyzer)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Beta-orange)

```
 .----------------.  .----------------.  .----------------.  .----------------. 
| .--------------. || .--------------. || .--------------. || .--------------. |
| |      __      | || |   _____      | || |  _________   | || |      __      | |
| |     /  \     | || |  |_   _|     | || | |_   ___  |  | || |     /  \     | |
| |    / /\ \    | || |    | |       | || |   | |_  \_|  | || |    / /\ \    | |
| |   / ____ \   | || |    | |   _   | || |   |  _|      | || |   / ____ \   | |
| | _/ /    \ \_ | || |   _| |__/ |  | || |  _| |_       | || | _/ /    \ \_ | |
| ||____|  |____|| || |  |________|  | || | |_____|      | || ||____|  |____|| |
| |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------' 
                                
Access & Logic Flaw Analyzer
By: Raihan Rinto Andiansyah & Ahmed Haykal Hifzhan Rachmady
```

---

## 📌 Description

**ALFA (Access & Logic Flaw Analyzer)** is an automated framework for web application security testing, focusing on detecting Access Control flaws, IDOR (Insecure Direct Object References), Privilege Escalation, and Business Logic flaws. In final testing within a multi-role lab environment, **ALFA demonstrated over 90% detection effectiveness** across simulated scenarios.

The tool helps identify critical issues such as:

* **IDOR (Insecure Direct Object References)**
* **Privilege Escalation (Horizontal & Vertical)**
* **Authentication bypass & brute-force resistance flaws**
* **Business logic abuse scenarios**

The main goal is to provide an **automated testing system** for:

* Crawling & user role mapping
* Authentication testing (manual & brute-force)
* OTP handling & abuse detection
* Access control verification across roles
* Automated reporting with response comparison

---

## ✨ Key Features

* 🔎 **Web Crawler** → Automatically maps endpoints and login pages.
* 🛠 **Directory Bruteforcer** → Wordlist-based endpoint discovery.
* 🔑 **Authentication Tester** → Supports manual login and brute-force.
* 📲 **OTP Handling** → Detects OTP requirement, supports manual/auto handling, and abuse (OTP request abuse) .
* 🛡 **WALF Tests** → Logic flaw & access control testing (IDOR, privilege escalation).
* 📑 **Report Generator** → Creates detailed security reports automatically.

---

## 🏗 Project Structure

```
.
├── alfa.py                # Main entrypoint
├── crawler.py              # Web crawler for login page & link discovery
├── bruteforce.py           # Directory brute-forcing engine
├── auth_tester.py          # Authentication testing module
├── reporter.py             # Report generation
├── walf.py                 # WALF (Web Access & Logic Flaw) test engine
├── data/                   # Output folder (wordlists, results, reports)
│   ├── wordlist.txt
│   ├── usernames.txt
│   ├── passwords.txt
└── README.md
```

---

## ⚡ Installation

### 1. Clone the repository

```bash
git clone https://github.com/username/LOGAC.git
cd LOGAC
```

### 2. (Optional) Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### Run LOGAC

```bash
python alfa.py
```

### Execution Flow

1. Enter target host (`http://example.com`).
2. Choose scan mode:

   * **Full scan** → entire wordlist.
   * **Login-only scan** → filtered wordlist for authentication endpoints.
3. The framework will:

   * Crawl the target and locate login forms
   * Test authentication (manual / brute-force)
   * Handle OTP (manual / automated)
   * Run **WALF tests** if login succeeds
4. A full report is generated in the `data/` folder.

---

## 📊 Expected Results

* Automated **crawler & user role mapping**
* **Access control testing report** with response comparison
* Detection of flaws such as:

  * IDOR
  * Privilege escalation
  * OTP abuse
  * Authentication bypass
* Study case results on **multi-role applications**

---

## ⚠️ Disclaimer

LOGAC is built **for research and educational purposes only**.
⚠️ Do **NOT** use this tool against systems without **explicit permission**.

---

## 👨‍💻 Authors

* **Raihan Rinto Andiansyah**
* **Ahmed Haykal Hifzhan Rachmady**

---
