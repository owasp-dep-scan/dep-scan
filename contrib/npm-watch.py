import json
import httpx

from depscan.lib.pkg_query import npm_pkg_risk

settings = {"interval": "1000", "count": "50", "include_docs": "true"}
url = "https://replicate.npmjs.com/_changes"

with httpx.stream("GET", url=url, params=settings, timeout=30) as r:
    for line in r.iter_lines():
        if line:
            line = line.removesuffix(",")
            try:
                json_obj = json.loads(line)
                npm_pkg = json_obj.get("id")
                doc = json_obj.get("doc")
                if doc.get("_deleted"):
                    continue
                risk_metrics = npm_pkg_risk(
                    json_obj.get("doc"), False, None, {"name": npm_pkg}
                )
                if risk_metrics and (
                    risk_metrics["risk_score"] > 0.4
                    or risk_metrics.get("pkg_includes_binary_risk")
                    or risk_metrics.get("pkg_attested_check")
                ):
                    print(npm_pkg, risk_metrics)
            except Exception as e:
                pass
