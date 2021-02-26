import json
import requests

from depscan.lib.pkg_query import npm_pkg_risk

settings = {"interval": "1000", "count": "50", "include_docs": "true"}
url = "https://replicate.npmjs.com/_changes"

r = requests.get(url, params=settings, stream=True)

for line in r.iter_lines():
    if line:
        line = line.decode("utf-8")[:-1]
        try:
            json_obj = json.loads(line)
            npm_pkg = json_obj.get("id")
            risk_metrics = npm_pkg_risk(json_obj.get("doc"), False, None)
            if risk_metrics and risk_metrics["risk_score"] > 0.6:
                print(npm_pkg, risk_metrics)
        except Exception as e:
            print (line, e)
            pass
