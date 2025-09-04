import asyncio
import os
import getpass
from urllib.parse import urljoin
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging
import sys
import signal
# Import modules
from crawler import WebCrawler
from auth_tester import AuthTester
from bruteforce import DirectoryBruteforcer
from reporter import generate_report
from walf import run_walf_tests

# Banner
BANNER = r"""
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
"""

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ALFA")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Interrupted by user. Exiting gracefully...")
    sys.exit(0)

async def main():
    """Main function for ALFA tool"""
    print(BANNER)
    
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        host = input("Enter target host (e.g., http://example.com): ").strip()
        output_dir = "data"
        os.makedirs(output_dir, exist_ok=True)
       
        if not host.startswith(('http://', 'https://')):
            host = 'http://' + host
       
        safe_host = host.replace('http://', '').replace('https://', '').rstrip('/')
        safe_host = safe_host.replace(':', '_').replace('/', '_')
       
        # File paths
        dir_output = f"data/dir_{safe_host}.txt"
        successful_logins_path = f"data/successful_logins_{safe_host}.txt"
        wordlist_path = "data/wordlist.txt"
        usernames_path = "data/usernames.txt"
        passwords_path = "data/passwords.txt"
       
        # Initialize crawler
        crawler = WebCrawler(host)
       
        try:
            # Check if wordlist exists
            if not os.path.exists(wordlist_path):
                print(f"[-] Wordlist not found at {wordlist_path}")
                return
           
            # Initialize bruteforcer
            bruteforcer = DirectoryBruteforcer(host, wordlist_path, dir_output)
           
            # Check if directory output already exists
            if os.path.exists(dir_output):
                with open(dir_output, 'r') as f:
                    valid_urls = [line.strip() for line in f if line.strip()]
                print(f"[+] File {dir_output} already exists, found {len(valid_urls)} URLs. Skipping brute force.")
            else:
                print("[?] Select scan mode:")
                print("1. Full (entire wordlist)")
                print("2. Login page only (authentication section only)")
                choice = input("Choice (1/2): ").strip()
               
                if choice == "2":
                    filtered_words = await bruteforcer.filter_wordlist_login_only()
                    if not filtered_words:
                        print("[-] No words found in authentication section, using full mode")
                        valid_urls = await bruteforcer.run(filter_auth=False)
                    else:
                        temp_wordlist_path = f"data/wordlist_auth_{safe_host}.tmp"
                        with open(temp_wordlist_path, 'w') as f:
                            for word in filtered_words:
                                f.write(word + '\n')
                        auth_bruteforcer = DirectoryBruteforcer(host, temp_wordlist_path, dir_output)
                        print(f"[*] Using authentication-only wordlist: {len(filtered_words)} words")
                        valid_urls = await auth_bruteforcer.run(filter_auth=False)
                        os.remove(temp_wordlist_path)
                else:
                    valid_urls = await bruteforcer.run(filter_auth=False)
           
            # Find login page
            login_page, login_form = await crawler.find_login_page(dir_output)
            if not login_form:
                print("[-] No login form found")
                return
           
            print("[+] Login form found:")
            print(f" URL: {login_page}")
            print(f" Action: {login_form.get('action', 'N/A')}")
            print(f" Method: {login_form.get('method', 'N/A')}")
           
            if login_form.get('inputs'):
                username_field_type = login_form['inputs'][0]['type'] if login_form['inputs'] else 'N/A'
            else:
                username_field_type = 'N/A'
           
            print(f" Username field: {login_form.get('username_field', 'N/A')} ({username_field_type})")
            print(f" Password field: {login_form.get('password_field', 'N/A')}")
            print(f" Form type: {'Complicated' if login_form.get('is_complicated') else 'Simple'}")
            print(" Inputs:")
            for inp in login_form.get('inputs', []):
                print(f" {inp.get('name', 'N/A')} ({inp.get('type', 'N/A')}) = {inp.get('value', '')}")
           
            # Determine username type
            username_type = 'username'
            if 'email' in login_form.get('username_field', '').lower() or (login_form.get('inputs') and login_form['inputs'][0]['type'] == 'email'):
                username_type = 'email'
            elif login_form.get('inputs') and login_form['inputs'][0]['type'] == 'number':
                username_type = 'phone'
            print(f"[+] Detected username type: {username_type}")
           
            # Initialize auth tester
            tester = AuthTester(host)
            tester.login_page_url = login_page
           
            successful_logins = []
            brute_success = None
            otp_brute_success = None
            manual_used = False
            blocked_usernames = []
            otp_abuse_success = None
           
            # Check for existing successful logins
            if os.path.exists(successful_logins_path):
                print(f"[+] Existing successful logins found. Re-test them? (y/N): ")
                re_test = input().strip().lower() == 'y'
                if re_test:
                    print("[+] Testing brute on existing logins...")
                    with open(successful_logins_path, 'r') as f:
                        for line in f:
                            if line.strip():
                                parts = line.strip().split(':')
                                if len(parts) >= 2:
                                    username, password = parts[0], parts[1]
                                    print(f"[*] Brute testing existing: {username}:[REDACTED]")
                                    success, otp_detected = tester.try_login(login_form, username, password)
                                    if tester.brute_force_detected:
                                        brute_success = False
                                        blocked_usernames.append(username)
                                        break
                                    if success:
                                        if otp_detected:
                                            print("[?] OTP mode for existing login: 1. Manual 2. Auto (brute): ")
                                            otp_choice = input().strip()
                                            otp_auto_mode = True if otp_choice == '2' else False
                                            otp_success, otp_brute, otp_abuse_success = await tester.handle_otp(
                                                crawler, 
                                                {'username': username, 'password': password}, 
                                                login_form,  # Parameter tambahan untuk abuse check
                                                auto_mode=None
                                            )
                                            if tester.brute_force_detected:
                                                print("[!] Brute force detected during OTP handling. Generating report.")
                                                directories = []
                                                if os.path.exists(dir_output):
                                                    with open(dir_output, 'r') as f:
                                                        directories = [line.strip() for line in f if line.strip()]
                                                generate_report(safe_host, directories, successful_logins, brute_success, otp_brute_success, manual_used, login_form, tester.otp_form, blocked_usernames, otp_abuse_success, login_page)
                                                return
                                            if otp_brute is not None:
                                                otp_brute_success = otp_brute
                                            if otp_success:
                                                successful_logins.append({'username': username, 'password': password, 'otp_required': False})
                                            else:
                                                successful_logins.append({'username': username, 'password': password, 'otp_required': True})
                                        else:
                                            successful_logins.append({'username': username, 'password': password, 'otp_required': False})
                                            tester.save_cookies(username)
                else:
                    print("[+] Skipping re-test, using existing logins without verification.")
                    with open(successful_logins_path, 'r') as f:
                        for line in f:
                            if line.strip():
                                parts = line.strip().split(':')
                                if len(parts) >= 2:
                                    successful_logins.append({'username': parts[0], 'password': parts[1], 'otp_required': False})
           
            # Login mode selection
            choice = input("[?] Login mode: 1. Manual 2. Auto (brute): ")
            auto_mode = choice == '2'
            if not auto_mode:
                manual_used = True
           
            if auto_mode:
                # Check if wordlists exist
                if not os.path.exists(usernames_path) or not os.path.exists(passwords_path):
                    print("[-] Wordlists for brute not found")
                    return
               
                usernames = [line.strip() for line in open(usernames_path, 'r')]
                passwords = [line.strip() for line in open(passwords_path, 'r')]
               
                for username in usernames:
                    if username in tester.successful_usernames or username in blocked_usernames:
                        continue
                    for password in passwords:
                        print('==========================================')
                        print(f"[*] Trying {username}:[REDACTED]")
                        print('==========================================')
                        success, otp_detected = tester.try_login(login_form, username, password)
                        if tester.brute_force_detected:
                            brute_success = False
                            blocked_usernames.append(username)
                            break
                        if success:
                            brute_success = True
                            if otp_detected:
                                # Panggil dengan 4 parameter termasuk login_form
                                otp_success, otp_brute, otp_abuse_success = await tester.handle_otp(
                                    crawler, 
                                    {'username': username, 'password': password}, 
                                    login_form,  # Parameter tambahan untuk abuse check
                                    auto_mode=None
                                )
                                if tester.brute_force_detected:
                                    print("[!] Brute force detected during OTP handling. Generating report.")
                                    directories = []
                                    if os.path.exists(dir_output):
                                        with open(dir_output, 'r') as f:
                                            directories = [line.strip() for line in f if line.strip()]
                                    generate_report(safe_host, directories, successful_logins, brute_success, otp_brute_success, manual_used, login_form, tester.otp_form, blocked_usernames, otp_abuse_success, login_page)
                                    return
                                otp_brute_success = otp_brute if otp_brute is not None else None
                                if otp_success:
                                    successful_logins.append({'username': username, 'password': password, 'otp_required': False})
                                else:
                                    successful_logins.append({'username': username, 'password': password, 'otp_required': True})
                            else:
                                successful_logins.append({'username': username, 'password': password, 'otp_required': False})
                                tester.save_cookies(username)
                            break
                    if tester.brute_force_detected:
                        continue
               
                # Check if all usernames are blocked
                if all(u in blocked_usernames for u in usernames):
                    print("[!] All usernames blocked.")
                    manual_choice = input("[?] Try manual login? (y/N): ").strip().lower()
                    if manual_choice != 'y':
                        print("[+] Generating report based on current results.")
                        directories = []
                        if os.path.exists(dir_output):
                            with open(dir_output, 'r') as f:
                                directories = [line.strip() for line in f if line.strip()]
                        generate_report(safe_host, directories, successful_logins, brute_success, otp_brute_success, manual_used, login_form, tester.otp_form, blocked_usernames, otp_abuse_success, login_page)
                        return
                    manual_used = True
                    auto_mode = False
           
            # Manual login mode
            if not auto_mode or manual_used:
                while True:
                    username = input("Username (empty to cancel) :")
                    if not username:  # Allow empty input to cancel
                        print("[+] Canceling manual login. Generating report based on current results.")
                        break
                    if any(login['username'] == username for login in successful_logins):
                        print(f"[!] Username {username} already successfully logged in. Generating report.")
                        break
                    password = getpass.getpass("Password (hidden input): ")
                    success, otp_detected = tester.try_login(login_form, username, password)
                    if tester.brute_force_detected:
                        blocked_usernames.append(username)
                        print(f"[!] Username {username} blocked. Try another username.")
                        continue_choice = input("[?] Continue manual login? (y/N): ").strip().lower()
                        if continue_choice != 'y':
                            print("[+] Generating report based on current results.")
                            break
                        continue
                    if success:
                        if otp_detected:
                            otp_success, otp_brute, otp_abuse_success = await tester.handle_otp(
                                crawler, 
                                {'username': username, 'password': password}, 
                                login_form,  
                                auto_mode=None
                            )
                            if tester.brute_force_detected:
                                print("[!] Brute force detected during OTP handling. Generating report.")
                                directories = []
                                if os.path.exists(dir_output):
                                    with open(dir_output, 'r') as f:
                                        directories = [line.strip() for line in f if line.strip()]
                                generate_report(safe_host, directories, successful_logins, brute_success, otp_brute_success, manual_used, login_form, tester.otp_form, blocked_usernames, otp_abuse_success, login_page)
                                return
                            otp_brute_success = otp_brute if otp_brute is not None else None
                            if otp_success:
                                successful_logins.append({'username': username, 'password': password, 'otp_required': False})
                                tester.save_cookies(username)
                            else:
                                successful_logins.append({'username': username, 'password': password, 'otp_required': True})
                        else:
                            successful_logins.append({'username': username, 'password': password, 'otp_required': False})
                            tester.save_cookies(username)
                        print("[+] Login successful. Generating report.")
                        break
           
            # Save successful logins
            if successful_logins and not os.path.exists(successful_logins_path):
                with open(successful_logins_path, 'a') as f:
                    for acc in successful_logins:
                        f.write(f"{acc['username']}:{acc['password']}\n")
           
            # Get directories
            directories = []
            if os.path.exists(dir_output):
                with open(dir_output, 'r') as f:
                    directories = [line.strip() for line in f if line.strip()]
           
            # Run WALF tests if we have successful logins
            walf_findings = []
            if successful_logins:
                print("[+] Running WALF tests for access control and logic flaws...")
               
                # Convert aiohttp cookies to requests cookies
                cookies_dict = {}
                for cookie in crawler.session.cookie_jar:
                    cookies_dict[cookie.key] = cookie.value
               
                # Create requests session with the cookies
                session = requests.Session()
                session.cookies.update(cookies_dict)
                session.headers.update({
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                })
               
                # Run WALF tests
                walf_findings = run_walf_tests(session, host, output_dir)
           
            # Generate report
            generate_report(safe_host, directories, successful_logins, brute_success,
                       otp_brute_success, manual_used, login_form, tester.otp_form,
                       blocked_usernames, otp_abuse_success, login_page, walf_findings)
       
        except Exception as e:
            print(f"[-] Error during execution: {str(e)}")
            logging.exception("An error occurred:")
            
        finally:
            await crawler.close()
            
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Unexpected error: {str(e)}")
        logging.exception("An unexpected error occurred:")

if __name__ == "__main__":
    asyncio.run(main())