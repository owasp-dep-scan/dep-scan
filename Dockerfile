FROM python:3.10 AS build-env

ARG CLI_VERSION
ARG BUILD_DATE

RUN groupadd --gid 1000 node \
  && useradd --uid 1000 --gid node --shell /bin/bash --create-home node

ENV NODE_VERSION 18.12.1

RUN ARCH= && dpkgArch="$(dpkg --print-architecture)" \
  && case "${dpkgArch##*-}" in \
    amd64) ARCH='x64';; \
    ppc64el) ARCH='ppc64le';; \
    s390x) ARCH='s390x';; \
    arm64) ARCH='arm64';; \
    armhf) ARCH='armv7l';; \
    i386) ARCH='x86';; \
    *) echo "unsupported architecture"; exit 1 ;; \
  esac \
  # gpg keys listed at https://github.com/nodejs/node#release-keys
  && set -ex \
  && for key in \
    4ED778F539E3634C779C87C6D7062848A1AB005C \
    141F07595B7B3FFE74309A937405533BE57C7D57 \
    74F12602B6F1C4E913FAA37AD3A89613643B6201 \
    61FC681DFB92A079F1685E77973F295594EC4689 \
    8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600 \
    890C08DB8579162FEE0DF9DB8BEAB4DFCF555EF4 \
    C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8 \
    C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C \
    108F52B48DB57BB0CC439B2997B01419BD92F80A \
  ; do \
      gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$key" || \
      gpg --batch --keyserver keyserver.ubuntu.com --recv-keys "$key" ; \
  done \
  && curl -fsSLO --compressed "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$ARCH.tar.xz" \
  && curl -fsSLO --compressed "https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt.asc" \
  && gpg --batch --decrypt --output SHASUMS256.txt SHASUMS256.txt.asc \
  && grep " node-v$NODE_VERSION-linux-$ARCH.tar.xz\$" SHASUMS256.txt | sha256sum -c - \
  && tar -xJf "node-v$NODE_VERSION-linux-$ARCH.tar.xz" -C /usr/local --strip-components=1 --no-same-owner \
  && rm "node-v$NODE_VERSION-linux-$ARCH.tar.xz" SHASUMS256.txt.asc SHASUMS256.txt \
  && ln -s /usr/local/bin/node /usr/local/bin/nodejs \
  && npm install -g @cyclonedx/cdxgen

COPY setup.py /appthreat/
COPY MANIFEST.in /appthreat/
COPY README.md /appthreat/
COPY depscan /appthreat/depscan
COPY vendor /appthreat/vendor
USER root

WORKDIR /appthreat
RUN python3 setup.py install \
    && rm -rf /appthreat/*

FROM python:3.10-slim

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

COPY --from=build-env /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=build-env /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=build-env /usr/local/bin/scan /usr/local/bin/scan
COPY --from=build-env /usr/local/bin/depscan /usr/local/bin/depscan
COPY --from=build-env /usr/local/bin/vdb /usr/local/bin/vdb
COPY --from=build-env /usr/local/bin/node /usr/local/bin/node
COPY --from=build-env /usr/local/bin/npm /usr/local/bin/npm

ENV VDB_HOME=/appthreat \
    PYTHONUNBUFFERED=1 \
    NVD_START_YEAR=2018 \
    GITHUB_PAGE_COUNT=2 \
    CDXGEN_CMD=/usr/local/lib/node_modules/@cyclonedx/cdxgen/bin/cdxgen

WORKDIR /appthreat

CMD [ "depscan" ]
