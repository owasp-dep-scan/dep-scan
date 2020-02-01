#!/bin/sh
#
# An example pre-push hook to perform dep-scan on the repo.
# Copy this file to .git/hooks/pre-push
echo '
  ___            _____ _                    _
 / _ \          |_   _| |                  | |
/ /_\ \_ __  _ __ | | | |__  _ __ ___  __ _| |_
|  _  | '_ \| '_ \| | | '_ \| '__/ _ \/ _` | __|
| | | | |_) | |_) | | | | | | | |  __/ (_| | |_
\_| |_/ .__/| .__/\_/ |_| |_|_|  \___|\__,_|\__|
      | |   | |
      |_|   |_|
'
docker_state=$(docker info >/dev/null 2>&1)
if [[ $? -ne 0 ]]; then
    echo "Docker does not seem to be running, please start the service or run the desktop application"
    exit 1
fi
docker pull quay.io/appthreat/dep-scan >/dev/null 2>&1

# Perform automatic scan
echo "Performing dep scan on the repo"
docker run --rm -e VULNDB_HOME=/db -e NVD_START_YEAR=2016 -v /tmp:/db -v $PWD:/app quay.io/appthreat/dep-scan scan --src /app --report_file /app/reports/depscan.json
