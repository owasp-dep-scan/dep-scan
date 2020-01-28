#!/usr/bin/env bash

while sleep 1; do
    ag -l | entr -cdrs 'docker build -t appthreat/dep-scan -f Dockerfile .'
done
