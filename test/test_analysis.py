import json
import os

import pytest

from depscan.lib import analysis
from depscan.lib.analysis import cvss_to_vdr_rating, get_version_range, split_cwe


@pytest.fixture
def test_data():
    results = []
    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "depscan-java.json",
        ),
        mode="r",
        encoding="utf-8",
    ) as fp:
        for line in fp:
            row = json.loads(line)
            results.append(row)
    return results


@pytest.fixture
def test_js_deps_data():
    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "data", "bom-js.json"
        ),
        mode="r",
        encoding="utf-8",
    ) as fp:
        bom_data = json.load(fp)
        return bom_data.get("dependencies")


@pytest.fixture
def test_bom_dependency_tree():
    return [
        {
            "ref": "pkg:maven/com.example/vuln-spring@0.0.1-SNAPSHOT?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework.boot/spring-boot-starter-jdbc@2.2.6.RELEASE?type=jar",
                "pkg:maven/mysql/mysql-connector-java@8.0.19?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-starter-thymeleaf@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.2.6.RELEASE?type=jar",
                "pkg:maven/com.auth0/java-jwt@3.10.2?type=jar",
                "pkg:maven/com.cronutils/cron-utils@9.1.5?type=jar",
                "pkg:maven/org.keycloak/keycloak-core@11.0.3?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-devtools@2.2.6.RELEASE?type=jar",
                "pkg:maven/commons-collections/commons-collections@3.2.2?type=jar",
                "pkg:maven/commons-io/commons-io@2.11.0?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-starter-test@2.2.6.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-starter-jdbc@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework.boot/spring-boot-starter@2.2.6.RELEASE?type=jar",
                "pkg:maven/com.zaxxer/HikariCP@3.4.2?type=jar",
                "pkg:maven/org.springframework/spring-jdbc@5.2.5.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-starter@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework.boot/spring-boot@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-autoconfigure@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-starter-logging@2.2.6.RELEASE?type=jar",
                "pkg:maven/jakarta.annotation/jakarta.annotation-api@1.3.5?type=jar",
                "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.yaml/snakeyaml@1.25?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-context@5.2.5.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework/spring-jcl@5.2.5.RELEASE?type=jar"
            ],
        },
        {
            "ref": "pkg:maven/org.springframework/spring-jcl@5.2.5.RELEASE?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.springframework/spring-context@5.2.5.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework/spring-aop@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-beans@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-expression@5.2.5.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.springframework/spring-aop@5.2.5.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework/spring-beans@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.springframework/spring-beans@5.2.5.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar"
            ],
        },
        {
            "ref": "pkg:maven/org.springframework/spring-expression@5.2.5.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar"
            ],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-autoconfigure@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework.boot/spring-boot@2.2.6.RELEASE?type=jar"
            ],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-starter-logging@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/ch.qos.logback/logback-classic@1.2.3?type=jar",
                "pkg:maven/org.apache.logging.log4j/log4j-to-slf4j@2.12.1?type=jar",
                "pkg:maven/org.slf4j/jul-to-slf4j@1.7.30?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/ch.qos.logback/logback-classic@1.2.3?type=jar",
            "dependsOn": [
                "pkg:maven/ch.qos.logback/logback-core@1.2.3?type=jar",
                "pkg:maven/org.slf4j/slf4j-api@1.7.30?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/ch.qos.logback/logback-core@1.2.3?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.slf4j/slf4j-api@1.7.30?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.apache.logging.log4j/log4j-to-slf4j@2.12.1?type=jar",
            "dependsOn": [
                "pkg:maven/org.slf4j/slf4j-api@1.7.30?type=jar",
                "pkg:maven/org.apache.logging.log4j/log4j-api@2.12.1?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.apache.logging.log4j/log4j-api@2.12.1?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.slf4j/jul-to-slf4j@1.7.30?type=jar",
            "dependsOn": ["pkg:maven/org.slf4j/slf4j-api@1.7.30?type=jar"],
        },
        {
            "ref": "pkg:maven/jakarta.annotation/jakarta.annotation-api@1.3.5?type=jar",
            "dependsOn": [],
        },
        {"ref": "pkg:maven/org.yaml/snakeyaml@1.25?type=jar", "dependsOn": []},
        {
            "ref": "pkg:maven/com.zaxxer/HikariCP@3.4.2?type=jar",
            "dependsOn": ["pkg:maven/org.slf4j/slf4j-api@1.7.30?type=jar"],
        },
        {
            "ref": "pkg:maven/org.springframework/spring-jdbc@5.2.5.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework/spring-beans@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-tx@5.2.5.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.springframework/spring-tx@5.2.5.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework/spring-beans@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/mysql/mysql-connector-java@8.0.19?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-starter-thymeleaf@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework.boot/spring-boot-starter@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.thymeleaf/thymeleaf-spring5@3.0.11.RELEASE?type=jar",
                "pkg:maven/org.thymeleaf.extras/thymeleaf-extras-java8time@3.0.4.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.thymeleaf/thymeleaf-spring5@3.0.11.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.thymeleaf/thymeleaf@3.0.11.RELEASE?type=jar",
                "pkg:maven/org.slf4j/slf4j-api@1.7.30?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.thymeleaf/thymeleaf@3.0.11.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.attoparser/attoparser@2.0.5.RELEASE?type=jar",
                "pkg:maven/org.unbescape/unbescape@1.1.6.RELEASE?type=jar",
                "pkg:maven/org.slf4j/slf4j-api@1.7.30?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.attoparser/attoparser@2.0.5.RELEASE?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.unbescape/unbescape@1.1.6.RELEASE?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.thymeleaf.extras/thymeleaf-extras-java8time@3.0.4.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.thymeleaf/thymeleaf@3.0.11.RELEASE?type=jar",
                "pkg:maven/org.slf4j/slf4j-api@1.7.30?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework.boot/spring-boot-starter@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-starter-json@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-starter-tomcat@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-starter-validation@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-web@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-webmvc@5.2.5.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-starter-json@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework.boot/spring-boot-starter@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-web@5.2.5.RELEASE?type=jar",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.3?type=jar",
                "pkg:maven/com.fasterxml.jackson.datatype/jackson-datatype-jdk8@2.10.3?type=jar",
                "pkg:maven/com.fasterxml.jackson.datatype/jackson-datatype-jsr310@2.10.3?type=jar",
                "pkg:maven/com.fasterxml.jackson.module/jackson-module-parameter-names@2.10.3?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.springframework/spring-web@5.2.5.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework/spring-beans@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.3?type=jar",
            "dependsOn": [
                "pkg:maven/com.fasterxml.jackson.core/jackson-annotations@2.10.3?type=jar",
                "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.10.3?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-annotations@2.10.3?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.10.3?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/com.fasterxml.jackson.datatype/jackson-datatype-jdk8@2.10.3?type=jar",
            "dependsOn": [
                "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.10.3?type=jar",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.3?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/com.fasterxml.jackson.datatype/jackson-datatype-jsr310@2.10.3?type=jar",
            "dependsOn": [
                "pkg:maven/com.fasterxml.jackson.core/jackson-annotations@2.10.3?type=jar",
                "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.10.3?type=jar",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.3?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/com.fasterxml.jackson.module/jackson-module-parameter-names@2.10.3?type=jar",
            "dependsOn": [
                "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.10.3?type=jar",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.3?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-starter-tomcat@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/jakarta.annotation/jakarta.annotation-api@1.3.5?type=jar",
                "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.33?type=jar",
                "pkg:maven/org.apache.tomcat.embed/tomcat-embed-el@9.0.33?type=jar",
                "pkg:maven/org.apache.tomcat.embed/tomcat-embed-websocket@9.0.33?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.33?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.apache.tomcat.embed/tomcat-embed-el@9.0.33?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.apache.tomcat.embed/tomcat-embed-websocket@9.0.33?type=jar",
            "dependsOn": [
                "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.33?type=jar"
            ],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-starter-validation@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework.boot/spring-boot-starter@2.2.6.RELEASE?type=jar",
                "pkg:maven/jakarta.validation/jakarta.validation-api@2.0.2?type=jar",
                "pkg:maven/org.hibernate.validator/hibernate-validator@6.0.18.Final?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/jakarta.validation/jakarta.validation-api@2.0.2?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.hibernate.validator/hibernate-validator@6.0.18.Final?type=jar",
            "dependsOn": [
                "pkg:maven/org.jboss.logging/jboss-logging@3.4.1.Final?type=jar",
                "pkg:maven/com.fasterxml/classmate@1.5.1?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.jboss.logging/jboss-logging@3.4.1.Final?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/com.fasterxml/classmate@1.5.1?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.springframework/spring-webmvc@5.2.5.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework/spring-aop@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-beans@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-context@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-expression@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-web@5.2.5.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/com.auth0/java-jwt@3.10.2?type=jar",
            "dependsOn": [
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.3?type=jar",
                "pkg:maven/commons-codec/commons-codec@1.13?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/commons-codec/commons-codec@1.13?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/com.cronutils/cron-utils@9.1.5?type=jar",
            "dependsOn": [
                "pkg:maven/org.slf4j/slf4j-api@1.7.30?type=jar",
                "pkg:maven/org.glassfish/javax.el@3.0.0?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.glassfish/javax.el@3.0.0?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.keycloak/keycloak-core@11.0.3?type=jar",
            "dependsOn": [
                "pkg:maven/org.keycloak/keycloak-common@11.0.3?type=jar",
                "pkg:maven/org.bouncycastle/bcprov-jdk15on@1.65?type=jar",
                "pkg:maven/org.bouncycastle/bcpkix-jdk15on@1.65?type=jar",
                "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.10.3?type=jar",
                "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.3?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.keycloak/keycloak-common@11.0.3?type=jar",
            "dependsOn": [
                "pkg:maven/org.bouncycastle/bcprov-jdk15on@1.65?type=jar",
                "pkg:maven/org.bouncycastle/bcpkix-jdk15on@1.65?type=jar",
                "pkg:maven/com.sun.activation/jakarta.activation@1.2.2?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.bouncycastle/bcprov-jdk15on@1.65?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.bouncycastle/bcpkix-jdk15on@1.65?type=jar",
            "dependsOn": ["pkg:maven/org.bouncycastle/bcprov-jdk15on@1.65?type=jar"],
        },
        {
            "ref": "pkg:maven/com.sun.activation/jakarta.activation@1.2.2?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-devtools@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework.boot/spring-boot@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-autoconfigure@2.2.6.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/commons-collections/commons-collections@3.2.2?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/commons-io/commons-io@2.11.0?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-starter-test@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework.boot/spring-boot-starter@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-test@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-test-autoconfigure@2.2.6.RELEASE?type=jar",
                "pkg:maven/com.jayway.jsonpath/json-path@2.4.0?type=jar",
                "pkg:maven/jakarta.xml.bind/jakarta.xml.bind-api@2.3.3?type=jar",
                "pkg:maven/org.junit.jupiter/junit-jupiter@5.5.2?type=jar",
                "pkg:maven/org.mockito/mockito-junit-jupiter@3.1.0?type=jar",
                "pkg:maven/org.assertj/assertj-core@3.13.2?type=jar",
                "pkg:maven/org.hamcrest/hamcrest@2.1?type=jar",
                "pkg:maven/org.mockito/mockito-core@3.1.0?type=jar",
                "pkg:maven/org.skyscreamer/jsonassert@1.5.0?type=jar",
                "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.springframework/spring-test@5.2.5.RELEASE?type=jar",
                "pkg:maven/org.xmlunit/xmlunit-core@2.6.4?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-test@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework.boot/spring-boot@2.2.6.RELEASE?type=jar"
            ],
        },
        {
            "ref": "pkg:maven/org.springframework.boot/spring-boot-test-autoconfigure@2.2.6.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework.boot/spring-boot-test@2.2.6.RELEASE?type=jar",
                "pkg:maven/org.springframework.boot/spring-boot-autoconfigure@2.2.6.RELEASE?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/com.jayway.jsonpath/json-path@2.4.0?type=jar",
            "dependsOn": [
                "pkg:maven/net.minidev/json-smart@2.3?type=jar",
                "pkg:maven/org.slf4j/slf4j-api@1.7.30?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/net.minidev/json-smart@2.3?type=jar",
            "dependsOn": ["pkg:maven/net.minidev/accessors-smart@1.2?type=jar"],
        },
        {
            "ref": "pkg:maven/net.minidev/accessors-smart@1.2?type=jar",
            "dependsOn": ["pkg:maven/org.ow2.asm/asm@5.0.4?type=jar"],
        },
        {"ref": "pkg:maven/org.ow2.asm/asm@5.0.4?type=jar", "dependsOn": []},
        {
            "ref": "pkg:maven/jakarta.xml.bind/jakarta.xml.bind-api@2.3.3?type=jar",
            "dependsOn": [
                "pkg:maven/jakarta.activation/jakarta.activation-api@1.2.2?type=jar"
            ],
        },
        {
            "ref": "pkg:maven/jakarta.activation/jakarta.activation-api@1.2.2?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.junit.jupiter/junit-jupiter@5.5.2?type=jar",
            "dependsOn": [
                "pkg:maven/org.junit.jupiter/junit-jupiter-api@5.5.2?type=jar",
                "pkg:maven/org.junit.jupiter/junit-jupiter-params@5.5.2?type=jar",
                "pkg:maven/org.junit.jupiter/junit-jupiter-engine@5.5.2?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.junit.jupiter/junit-jupiter-api@5.5.2?type=jar",
            "dependsOn": [
                "pkg:maven/org.apiguardian/apiguardian-api@1.1.0?type=jar",
                "pkg:maven/org.opentest4j/opentest4j@1.2.0?type=jar",
                "pkg:maven/org.junit.platform/junit-platform-commons@1.5.2?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.apiguardian/apiguardian-api@1.1.0?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.opentest4j/opentest4j@1.2.0?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.junit.platform/junit-platform-commons@1.5.2?type=jar",
            "dependsOn": ["pkg:maven/org.apiguardian/apiguardian-api@1.1.0?type=jar"],
        },
        {
            "ref": "pkg:maven/org.junit.jupiter/junit-jupiter-params@5.5.2?type=jar",
            "dependsOn": [
                "pkg:maven/org.apiguardian/apiguardian-api@1.1.0?type=jar",
                "pkg:maven/org.junit.jupiter/junit-jupiter-api@5.5.2?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.junit.jupiter/junit-jupiter-engine@5.5.2?type=jar",
            "dependsOn": [
                "pkg:maven/org.apiguardian/apiguardian-api@1.1.0?type=jar",
                "pkg:maven/org.junit.platform/junit-platform-engine@1.5.2?type=jar",
                "pkg:maven/org.junit.jupiter/junit-jupiter-api@5.5.2?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.junit.platform/junit-platform-engine@1.5.2?type=jar",
            "dependsOn": [
                "pkg:maven/org.apiguardian/apiguardian-api@1.1.0?type=jar",
                "pkg:maven/org.opentest4j/opentest4j@1.2.0?type=jar",
                "pkg:maven/org.junit.platform/junit-platform-commons@1.5.2?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.mockito/mockito-junit-jupiter@3.1.0?type=jar",
            "dependsOn": [
                "pkg:maven/org.mockito/mockito-core@3.1.0?type=jar",
                "pkg:maven/org.junit.jupiter/junit-jupiter-api@5.5.2?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/org.mockito/mockito-core@3.1.0?type=jar",
            "dependsOn": [
                "pkg:maven/net.bytebuddy/byte-buddy@1.10.8?type=jar",
                "pkg:maven/net.bytebuddy/byte-buddy-agent@1.10.8?type=jar",
                "pkg:maven/org.objenesis/objenesis@2.6?type=jar",
            ],
        },
        {
            "ref": "pkg:maven/net.bytebuddy/byte-buddy@1.10.8?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/net.bytebuddy/byte-buddy-agent@1.10.8?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.objenesis/objenesis@2.6?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.assertj/assertj-core@3.13.2?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.hamcrest/hamcrest@2.1?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.skyscreamer/jsonassert@1.5.0?type=jar",
            "dependsOn": [
                "pkg:maven/com.vaadin.external.google/android-json@0.0.20131108.vaadin1?type=jar"
            ],
        },
        {
            "ref": "pkg:maven/com.vaadin.external.google/android-json@0.0.20131108.vaadin1?type=jar",
            "dependsOn": [],
        },
        {
            "ref": "pkg:maven/org.springframework/spring-test@5.2.5.RELEASE?type=jar",
            "dependsOn": [
                "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar"
            ],
        },
        {
            "ref": "pkg:maven/org.xmlunit/xmlunit-core@2.6.4?type=jar",
            "dependsOn": [],
        },
    ]


def test_suggestion(test_data):
    sug = analysis.suggest_version(test_data)
    assert sug == {
        "com.fasterxml.jackson.core:jackson-databind": "2.9.10.4",
    }


def test_best_fixed_location():
    assert analysis.best_fixed_location("1.0.3", "1.0.2") == "1.0.3"
    assert analysis.best_fixed_location("3.0.3", "1.0.2") == "1.0.2"
    assert analysis.best_fixed_location(None, "1.0.2") == "1.0.2"
    assert analysis.best_fixed_location("4.0.0", None) == "4.0.0"


def test_locate_pkg_in_tree(test_bom_dependency_tree, test_js_deps_data):
    assert analysis.pkg_sub_tree(
        "pkg:maven/org.yaml/snakeyaml@1.25?type=jar",
        "",
        test_bom_dependency_tree,
    )[0] == [
        "pkg:maven/org.springframework.boot/spring-boot-starter-jdbc@2.2.6.RELEASE?type=jar",
        "pkg:maven/org.springframework.boot/spring-boot-starter@2.2.6.RELEASE?type=jar",
        "pkg:maven/org.yaml/snakeyaml@1.25?type=jar",
    ]
    assert analysis.pkg_sub_tree(
        "pkg:maven/org.keycloak/keycloak-core@11.0.3?type=jar",
        "",
        test_bom_dependency_tree,
    )[0] == ["pkg:maven/org.keycloak/keycloak-core@11.0.3?type=jar"]
    assert analysis.pkg_sub_tree(
        "",
        "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.33?type=jar",
        test_bom_dependency_tree,
    )[0] == [
        "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.2.6.RELEASE?type=jar",
        "pkg:maven/org.springframework.boot/spring-boot-starter-tomcat@2.2.6.RELEASE?type=jar",
        "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.33?type=jar",
    ]
    assert analysis.pkg_sub_tree(
        "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
        "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
        test_bom_dependency_tree,
    )[0] == [
        "pkg:maven/org.springframework.boot/spring-boot-starter-jdbc@2.2.6.RELEASE?type=jar",
        "pkg:maven/org.springframework.boot/spring-boot-starter@2.2.6.RELEASE?type=jar",
        "pkg:maven/org.springframework/spring-core@5.2.5.RELEASE?type=jar",
    ]
    assert analysis.pkg_sub_tree(
        "",
        "org.yaml/snakeyaml",
        test_bom_dependency_tree,
    )[0] == [
        "pkg:maven/org.springframework.boot/spring-boot-starter@2.2.6.RELEASE?type=jar",
        "pkg:maven/org.yaml/snakeyaml@1.25?type=jar",
    ]
    assert analysis.pkg_sub_tree(
        "pkg:maven/org.apache.logging.log4j/log4j-api@2.12.1?type=jar",
        None,
        test_bom_dependency_tree,
    )[0] == [
        "pkg:maven/org.springframework.boot/spring-boot-starter-logging@2.2.6.RELEASE?type=jar",
        "pkg:maven/org.apache.logging.log4j/log4j-to-slf4j@2.12.1?type=jar",
        "pkg:maven/org.apache.logging.log4j/log4j-api@2.12.1?type=jar",
    ]
    assert analysis.pkg_sub_tree(
        "pkg:maven/net.minidev/json-smart@2.3?type=jar",
        "pkg:maven/net.minidev/json-smart@2.3?type=jar",
        test_bom_dependency_tree,
    )[0] == [
        "pkg:maven/org.springframework.boot/spring-boot-starter-test@2.2.6.RELEASE?type=jar",
        "pkg:maven/com.jayway.jsonpath/json-path@2.4.0?type=jar",
        "pkg:maven/net.minidev/json-smart@2.3?type=jar",
    ]
    assert analysis.pkg_sub_tree(
        "pkg:npm/engine.io@6.2.1",
        "",
        test_js_deps_data,
    )[
        0
    ] == ["pkg:npm/socket.io@4.5.4", "pkg:npm/engine.io@6.2.1"]


def test_purl_usages():
    test_evinse_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "data", "bom-evinse-java.json"
    )
    direct_purls, reached_purls = analysis.find_purl_usages(
        test_evinse_file, None, None
    )
    assert direct_purls == {
        "pkg:maven/org.springframework/spring-jdbc@5.2.5.RELEASE?type=jar": 5,
        "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.33?type=jar": 12,
        "pkg:maven/org.springframework/spring-context@5.2.5.RELEASE?type=jar": 12,
        "pkg:maven/com.auth0/java-jwt@3.10.2?type=jar": 4,
        "pkg:maven/org.slf4j/slf4j-api@1.7.30?type=jar": 2,
        "pkg:maven/org.springframework.boot/spring-boot@2.2.6.RELEASE?type=jar": 1,
        "pkg:maven/commons-io/commons-io@2.11.0?type=jar": 2,
    }
    assert not reached_purls


def test_split_cwe():
    assert split_cwe("['CWE-20', 'CWE-668']") == [20, 668]
    assert split_cwe("CWE-1333") == [1333]
    assert split_cwe("") == ([])
    assert split_cwe("CWE-20") == ([20])
    assert split_cwe(None) == ([])
    assert split_cwe("[CWE-20, CWE-1333]") == ([20, 1333])


def test_cvss_to_vdr_rating():
    res = {
        "cvss_v3": {},
        "severity": "HIGH",
    }
    # Test missing score and vector string
    assert cvss_to_vdr_rating(res) == [
        {'method': 'CVSSv31', 'score': 2.0, 'severity': 'high'}]
    # Test parsing
    res["cvss_v3"]["vector_string"] = ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I"
                                       ":N/A:H")
    res["cvss_score"] = 7.5

    assert cvss_to_vdr_rating(res) == [{
        'method': 'CVSSv31',
        'score': 7.5,
        'severity': 'high',
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
    }]
    res["cvss_v3"]["vector_string"] = ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I"
                                       ":N/A:H")
    assert cvss_to_vdr_rating(res) == [{
        'method': 'CVSSv3',
        'score': 7.5,
        'severity': 'high',
        'vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'
    }]


def test_get_version_range():
    # Test empty
    assert get_version_range({}, "") == {}

    # Test all components present
    package_issue = {
        'affected_location': {
            'version': '>=2.9.0-<3.0.0'
        }, 'fixed_location': '3.0.0'}
    purl = "pkg:maven/org.apache.logging.log4j/log4j-api@2.12.1?type=jar"
    assert get_version_range(package_issue, purl) == {
        "name": "affectedVersionRange",
        "value": "org.apache.logging.log4j/log4j-api@>=2.9.0-<3.0.0"
    }

    # Test invalid purl
    purl = "maven/org.apache.logging.log4j/log4j-api@2.12.1?type=jar"
    assert get_version_range(package_issue, purl) == {
        'name': 'affectedVersionRange',
        'value': 'maven/org.apache.logging.log4j/log4j-api@>=2.9.0-<3.0.0'}


