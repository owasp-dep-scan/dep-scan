FROM python:3-slim AS build-env

ARG CLI_VERSION
ARG BUILD_DATE

COPY setup.py /appthreat/
COPY README.md /appthreat/
COPY depscan /appthreat/depscan
USER root

WORKDIR /appthreat
RUN python3 setup.py install \
    && rm -rf /appthreat/*

FROM python:3-slim

LABEL maintainer="AppThreat" \
      org.label-schema.schema-version="1.0" \
      org.label-schema.vendor="AppThreat" \
      org.label-schema.name="dep-scan" \
      org.label-schema.version=$CLI_VERSION \
      org.label-schema.license="MIT" \
      org.label-schema.description="Fully open-source security audit tool for project dependencies based on known vulnerabilities and advisories" \
      org.label-schema.url="https://appthreat.io" \
      org.label-schema.usage="https://github.com/appthreat/dep-scan" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/appthreat/dep-scan.git" \
      org.label-schema.docker.cmd="docker run --rm -it --name dep-scan appthreat/dep-scan"

COPY --from=build-env /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
COPY --from=build-env /usr/local/bin/scan /usr/local/bin/scan
COPY --from=build-env /usr/local/bin/vdb /usr/local/bin/vdb

ENV VULNDB_HOME=/appthreat \
    NVD_START_YEAR=2018 \
    GITHUB_PAGE_COUNT=2

WORKDIR /appthreat

CMD [ "scan" ]
