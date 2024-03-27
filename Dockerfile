FROM almalinux:9.3-minimal

LABEL maintainer="AppThreat" \
      org.opencontainers.image.authors="Team AppThreat <cloud@appthreat.com>" \
      org.opencontainers.image.source="https://github.com/owasp-dep-scan/dep-scan" \
      org.opencontainers.image.url="https://appthreat.com" \
      org.opencontainers.image.version="5.2.x" \
      org.opencontainers.image.vendor="appthreat" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="dep-scan" \
      org.opencontainers.image.description="Fully open-source security audit tool for project dependencies based on known vulnerabilities and advisories" \
      org.opencontainers.docker.cmd="docker run --rm -v /tmp:/tmp -p 7070:7070 -v $(pwd):/app:rw -t ghcr.io/owasp-dep-scan/dep-scan --server"

ARG TARGETPLATFORM
ARG JAVA_VERSION=21.0.2-graalce
ARG SBT_VERSION=1.9.8
ARG MAVEN_VERSION=3.9.6
ARG GRADLE_VERSION=8.5
ARG NYDUS_VERSION=2.2.4
ENV GOPATH=/opt/app-root/go \
    GO_VERSION=1.21.5 \
    JAVA_VERSION=$JAVA_VERSION \
    SBT_VERSION=$SBT_VERSION \
    MAVEN_VERSION=$MAVEN_VERSION \
    GRADLE_VERSION=$GRADLE_VERSION \
    NYDUS_VERSION=$NYDUS_VERSION \
    GRADLE_OPTS="-Dorg.gradle.daemon=false" \
    JAVA_HOME="/opt/java/${JAVA_VERSION}" \
    MAVEN_HOME="/opt/maven/${MAVEN_VERSION}" \
    GRADLE_HOME="/opt/gradle/${GRADLE_VERSION}" \
    SBT_HOME="/opt/sbt/${SBT_VERSION}" \
    COMPOSER_ALLOW_SUPERUSER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING="utf-8" \
    CDXGEN_CMD=cdxgen
ENV PATH=${PATH}:${JAVA_HOME}/bin:${MAVEN_HOME}/bin:${GRADLE_HOME}/bin:${SBT_HOME}/bin:${GOPATH}/bin:/usr/local/go/bin:/usr/local/bin/:/root/.local/bin:

COPY . /opt/dep-scan

RUN set -e; \
    ARCH_NAME="$(rpm --eval '%{_arch}')"; \
    url=; \
    case "${ARCH_NAME##*-}" in \
        'x86_64') \
            OS_ARCH_SUFFIX=''; \
            GOBIN_VERSION='amd64'; \
            ;; \
        'aarch64') \
            OS_ARCH_SUFFIX='-aarch64'; \
            GOBIN_VERSION='arm64'; \
            ;; \
        *) echo >&2 "error: unsupported architecture: '$ARCH_NAME'"; exit 1 ;; \
    esac; \
    echo -e "[nodejs]\nname=nodejs\nstream=20\nprofiles=\nstate=enabled\n" > /etc/dnf/modules.d/nodejs.module \
    && microdnf module enable php ruby -y \
    && microdnf install -y php php-curl php-zip php-bcmath php-json php-pear php-mbstring php-devel make gcc git-core \
        python3.11 python3.11-devel python3.11-pip ruby ruby-devel \
        libX11-devel libXext-devel libXrender-devel libjpeg-turbo-devel \
        pcre2 which tar zip unzip sudo nodejs ncurses glibc-common glibc-all-langpacks xorg-x11-fonts-75dpi xorg-x11-fonts-Type1 \
    && alternatives --install /usr/bin/python3 python /usr/bin/python3.11 1 \
    && python3 --version \
    && node --version \
    && python3 -m pip install --upgrade pip \
    && curl -LO https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox-0.12.6.1-2.almalinux9.${ARCH_NAME}.rpm \
    && rpm -ivh wkhtmltox-0.12.6.1-2.almalinux9.${ARCH_NAME}.rpm \
    && rm wkhtmltox-0.12.6.1-2.almalinux9.${ARCH_NAME}.rpm \
    && curl -s "https://get.sdkman.io" | bash \
    && source "$HOME/.sdkman/bin/sdkman-init.sh" \
    && echo -e "sdkman_auto_answer=true\nsdkman_selfupdate_feature=false\nsdkman_auto_env=true\nsdkman_curl_connect_timeout=20\nsdkman_curl_max_time=0" >> $HOME/.sdkman/etc/config \
    && sdk install java $JAVA_VERSION \
    && sdk install maven $MAVEN_VERSION \
    && sdk install gradle $GRADLE_VERSION \
    && sdk install sbt $SBT_VERSION \
    && sdk offline enable \
    && mv /root/.sdkman/candidates/* /opt/ \
    && rm -rf /root/.sdkman \
    && npm install -g @cyclonedx/cdxgen@10.2.5 \
    && cdxgen --version \
    && curl -LO "https://dl.google.com/go/go${GO_VERSION}.linux-${GOBIN_VERSION}.tar.gz" \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-${GOBIN_VERSION}.tar.gz \
    && rm go${GO_VERSION}.linux-${GOBIN_VERSION}.tar.gz \
    && useradd -ms /bin/bash appthreat \
    && pecl channel-update pecl.php.net \
    && pecl install timezonedb \
    && echo 'extension=timezonedb.so' >> /etc/php.ini \
    && php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" && php composer-setup.php \
    && mv composer.phar /usr/local/bin/composer \
    && python3 -m pip install pipenv certifi \
    && curl -LO https://github.com/dragonflyoss/nydus/releases/download/v${NYDUS_VERSION}/nydus-static-v${NYDUS_VERSION}-linux-${GOBIN_VERSION}.tgz \
    && tar -xvf nydus-static-v${NYDUS_VERSION}-linux-${GOBIN_VERSION}.tgz \
    && chmod +x nydus-static/* \
    && mv nydus-static/* /usr/local/bin/ \
    && rm -rf nydus-static-v${NYDUS_VERSION}-linux-${GOBIN_VERSION}.tgz nydus-static \
    && cd /opt/dep-scan \
    && python3 -m pip install -e . \
    && chmod a-w -R /opt \
    && rm -rf /var/cache/yum \
    && microdnf clean all

ENTRYPOINT [ "depscan" ]
