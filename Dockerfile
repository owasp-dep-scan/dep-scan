FROM python:3.9 AS build-env

ARG CLI_VERSION
ARG BUILD_DATE

RUN groupadd --gid 1000 node \
  && useradd --uid 1000 --gid node --shell /bin/bash --create-home node

ENV NODE_VERSION 16.13.1

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
    94AE36675C464D64BAFA68DD7434390BDBE9B9C5 \
    74F12602B6F1C4E913FAA37AD3A89613643B6201 \
    71DCFD284A79C3B38668286BC97EC7A07EDE3FC1 \
    8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600 \
    C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8 \
    C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C \
    DD8F2338BAE7501E3DD5AC78C273792F7D83545D \
    A48C2BEE680E841632CD4E44F07496B3EB3C1762 \
    108F52B48DB57BB0CC439B2997B01419BD92F80A \
    B9E2F5981AA6E0CD28160D9FF13993A75599653C \
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
  && npm install -g @ngcloudsec/cdxgen-plugins-bin \
  && npm install -g @appthreat/cdxgen

COPY setup.py /appthreat/
COPY MANIFEST.in /appthreat/
COPY README.md /appthreat/
COPY depscan /appthreat/depscan
COPY vendor /appthreat/vendor
USER root

WORKDIR /appthreat
RUN python3 setup.py install \
    && rm -rf /appthreat/*

FROM python:3.9-slim

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
COPY --from=build-env /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=build-env /usr/local/bin/scan /usr/local/bin/scan
COPY --from=build-env /usr/local/bin/depscan /usr/local/bin/depscan
COPY --from=build-env /usr/local/bin/vdb /usr/local/bin/vdb
COPY --from=build-env /usr/local/bin/node /usr/local/bin/node
COPY --from=build-env /usr/local/bin/npm /usr/local/bin/npm

ENV VDB_HOME=/appthreat \
    PYTHONUNBUFFERED=1 \
    NVD_START_YEAR=2018 \
    GITHUB_PAGE_COUNT=2 \
    CDXGEN_CMD=/usr/local/lib/node_modules/@appthreat/cdxgen/bin/cdxgen

WORKDIR /appthreat

CMD [ "depscan" ]
