import json
import urllib.request

def post(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:
        print(f"POST {url}")
        print(resp.read().decode("utf-8"))
        print()

# On terminal, run: 
# for rule setup:               python3 -c "import demo; demo.rule_setup()"
# for sending payload:          python3 -c "import demo; demo.send_payload()"
# for sending benign payload:   python3 -c "import demo; demo.send_benign_payload()"

def rule_setup():
    post("http://localhost:8001/rules/add", {"keyword": "attackat", "rule_id": "attackat"})
    post("http://localhost:8001/rules/publish", {})

def send_payload():
    post("http://localhost:8003/send", {"payload": "attackatattackat"})

def send_benign_payload():
    post("http://localhost:8003/send", {"payload": "normal browsing activity"})