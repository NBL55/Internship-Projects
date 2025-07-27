import requests
from bs4 import BeautifulSoup
import re
from flask import Flask, request, render_template_string
import csv
import json
from datetime import datetime
from urllib.parse import urljoin

app = Flask(__name__)

html_ui = """
<!doctype html>
<html>
<head><title>Web Vulnerability Scanner</title></head>
<body>
<h2>Web Vulnerability Scanner</h2>
<form method="post">
<label>Target URL:</label>
<input type="text" name="url" size="50" required>
<input type="submit" value="Scan">
</form>
{% if results %}
<h3>Scan Results:</h3>
<ul>
{% for result in results %}<li>{{ result }}</li>{% endfor %}
</ul>
{% endif %}
</body>
</html>
"""

test_payloads = {
    "XSS": "<script>alert(1)</script>",
    "SQLi": "' OR '1'='1"
}

def log_to_csv(target_url, result):
    with open("logs/scan_results.csv", "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([datetime.now(), target_url, result])

def log_to_json(target_url, results):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target_url": target_url,
        "results": results
    }
    try:
        with open("logs/scan_results.json", "r") as jsonfile:
            data = json.load(jsonfile)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []
    data.append(log_entry)
    with open("logs/scan_results.json", "w") as jsonfile:
        json.dump(data, jsonfile, indent=4)

def scan_xss_sql_injection(target_url):
    results = []
    try:
        r = requests.get(target_url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all(["input", "textarea"])
            data = {}
            for input_tag in inputs:
                input_name = input_tag.get("name")
                if input_name:
                    data[input_name] = test_payloads["XSS"]
            action_url = urljoin(target_url, action) if action else target_url
            if method == "post":
                res = requests.post(action_url, data=data, timeout=5)
            else:
                res = requests.get(action_url, params=data, timeout=5)
            if test_payloads["XSS"] in res.text:
                results.append(f"[+] Potential XSS detected in {action_url}")
            if re.search(r"(SQL syntax|mysql_fetch|ORA-)", res.text, re.I):
                results.append(f"[+] Potential SQL Injection detected in {action_url}")
        if not results:
            results.append("[-] No vulnerabilities detected with basic tests.")
    except Exception as e:
        results.append(f"[Error] {e}")
    return results

@app.route('/', methods=['GET', 'POST'])
def home():
    results = []
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            results = scan_xss_sql_injection(url)
            for result in results:
                log_to_csv(url, result)
            log_to_json(url, results)
    return render_template_string(html_ui, results=results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)