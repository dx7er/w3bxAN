import os, time, pyfiglet
import platform, requests, argparse
from  pprint  import  pprint
from urllib.parse import urljoin
from bs4 import BeautifulSoup as bs

# initialize an HTTP session & set the browser
sesson = requests.Session()
sesson.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    soup = bs(sesson.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    details = {}
    #get form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    
    #get form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    
    #getting input detials such as type and name
    inputs = []
    
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append(
            {"type": input_type, "name": input_name, "value": input_value})
    
    #putting everything to the details dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):
    #constructing full URL
    target_url = urljoin(url, form_details["action"])
    
    #taking inputs
    inputs = form_details["inputs"]
    data = {}
    
    for input in inputs:
        #replaceing text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        
        input_name = input.get("name")
        input_value = input.get("value")
        
        if input_name and input_value:
            #if input name and value are not None,
            #then add them to the data of form submission
            data[input_name] = input_value

    print(f"[+] Submitting malicious payload to {target_url}")
    print(f"[+] Data: {data}")
    
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    
    else:
        # GET request
        return requests.get(target_url, params=data)

def is_vulnerable(response):
    errors = {
        #MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        #SQL Server
        "unclosed quotation mark after the character string",
        #Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        #if any errors found, return True
        if error in response.content.decode().lower():
            return True
    #no error detected
    return False 


def scan_sql_injection(url):
    #testing on URL
    for c in "\"'":
        #add quote/double quote character to the URL
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)
        #making HTTP request
        res = sesson.get(new_url)
        
        if is_vulnerable(res):
            #SQL Injection detected on the URL itself,
            #no need to preceed for extracting forms and submitting them
            print("[!] SQL Injection vulnerability detected, link:", new_url)
            time.sleep(3)
            print("[+] Remedation: Update you system on regular basis.")
            return
    
    #test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            #the data body to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"
            
            #joining the url with the action (form request URL)
            url = urljoin(url, form_details["action"])
            
            if form_details["method"] == "post":
                res = sesson.post(url, data=data)
            
            elif form_details["method"] == "get":
                res = sesson.get(url, params=data)
            
            #testing whether the resulting page is vulnerable
            if is_vulnerable(res):
                time.sleep(3)
                print("[+] SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                pprint(form_details)
                break
            else:
                time.sleep(3)
                print("[!] No SQL Vulnerability Detected.")


def scan_xss(url):
    # geting all the forms from the URL
    forms = get_all_forms(url)
    
    time.sleep(3)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<Script>alert('hi')</scripT>"
    
    #returning value
    is_vulnerable = False
    
    #iterating over forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[!] XSS Detected on {url}")
            print(f"[!] Form details:")
            pprint(form_details)
            is_vulnerable = True
            print("[+] Remedition: Use sanitization Librairies and User Input Validtion Techinuqes")
        else:
            print("[!] No XSS Vulnerability Detected.")
        
    return is_vulnerable


def remote_code_execution(url):
    payload = "system('ls');"
    #sending request to the URL with the payload and retrieve the response
    response = requests.get(url, params={"input": payload})

    #check the response for the presence of certain strings or patterns that may indicate a vulnerability
    if "total" in response.text:
        print("[!] Possible RCE vulnerability detected: command output found in response")
        print("[+] Remedation: Use Secure Coding Practices.")
        
    else:
        print("[!] No Remote Code Execution Vulnerability Detected.")


def security_misconfiguration(url):
    #send a request to the URL and retrieve the response
    response = requests.get(url)

    #check the response for the presence of certain strings or patterns that may indicate a vulnerability
    if "Server" in response.headers:
        print("[!] Security Misconfiguration: Server Software Version found in Response.")
        print("[+] Remedation: Use Latest Security Framework.")
    
    elif "X-Powered-By" in response.headers:
        print("[!] Security Misconfiguration: Server Framework found in Response.")
        print("[+] Remedation: Use Latest Security Framework.")
    
    elif "Set-Cookie" in response.headers:
        print("[!] Security Misconfiguration: Insecure Cookies found in Response.")
        print("[+] Remedation: Use Latest Security Framework.")
        
    else:
        print("[!] No Security Misconfiguration Vulnerability Detected.")


def broken_auth(url):
    #set the login credentials
    username = "test"
    password = "password"

    #send a request to the login page with the credentials and retrieve the response
    response = requests.post(
        url, data={"username": username, "password": password})

    #check the response for the presence of certain strings or patterns that may indicate a vulnerability
    if "incorrect" in response.text:
        print("[!] Broken Authentication Detected: Incorrect Login Credentials.")
        print("[+] Remedation: Implement Two Factor Authentication.")
        
    elif "session" in response.cookies:
        print("[!] Broken Authentication Detected: Session Cookie Found in Response.")
        print("[+] Remedation: Implement Two Factor Authentication.")
    
    else:
        print("[!] No Broken Authenitcation Vulnerability Detected.")
        print("[+] Remedation: Implement Two Factor Authentication.")


def csrf_scan(url):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"input": "test"}
    
    #sending a request to the URL and retrieve the response
    response = requests.post(url, headers=headers, data=data)

    #checking the response for the presence of certain strings or patterns that may indicate a vulnerability
    if "error" in response.text:
        print("[!] CSRF Vulnerability Detected: Error Message found in Response.")
        print("[+] Remedation: Use CAPTCHA or Anti-CSRF Token.")
    
    else:
        print("[!] No CSRF Vulnerability Found.")
        
def banner():
    #printing name of scanner "WebPloit" to User
    banr=pyfiglet.figlet_format("w3bxAN")
    print(banr)


if __name__=="__main__":
    if platform.system()=='Linux':
        os.system('clear')

    #if os is windows clear using below command    
    elif platform.system()=='Windows':
        os.system('cls')
    
    #calling banner function    
    banner()
        
    #command line arguements
    parser = argparse.ArgumentParser(description='A tool for scanning websites for common vulnerabilities.')
    parser.add_argument('url', help='The URL of the website to scan')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='The timeout for each request (in seconds)')
    parser.add_argument('-o', '--output', type=str, default='report.txt', help='The name of the output file')
    args = parser.parse_args()
    
    print('[*] Target URL:', args.url)
    print('[*] Timeout:', args.timeout)
    print('[*] Output file:', args.output)
    
    #peforming vulnerability scans
    time.sleep(args.timeout)
    scan_sql_injection(args.url)
    
    time.sleep(args.timeout)
    scan_xss(args.url)
    
    time.sleep(args.timeout)
    remote_code_execution(args.url)
    
    time.sleep(args.timeout)
    security_misconfiguration(args.url)
    
    time.sleep(args.timeout)
    broken_auth(args.url)
    
    time.sleep(args.timeout)
    csrf_scan(args.url)
    
    print('[*] Generating Report.')
    with open(args.output, 'w') as f:
        f.write('Vulnerability scan report for ' + args.url + ':\n\n')
        f.write(scan_sql_injection(args.url))
        f.write('\n\n')
        f.write(scan_xss(args.url))
        f.write('\n\n')
        f.write(remote_code_execution(args.url))
        f.write('\n\n')
        f.write(security_misconfiguration(args.url))
        f.write('\n\n')
        f.write(broken_auth(args.url))
        f.write('\n\n')
        f.write(csrf_scan(args.url))
        f.write('\n\n')

    print('[*] Report saved to', args.output)
