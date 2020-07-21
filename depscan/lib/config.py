import os

license_data_dir = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    "..",
    "..",
    "vendor",
    "choosealicense.com",
    "_licenses",
)

# CPE Vendor aliases
vendor_alias = {
    "org.apache.tomcat": "apache_tomcat",
    "org.apache.commons.io": "commons-io",
    "org.apache.logging.log4j": "log4j",
    "org.apache.commons.beanutils": "commons-beanutils",
    "org.apache.commons.collections": "commons-collections",
    "org.apache.solr": "apache_solr",
    "org.springframework": "pivotal_software",
    "io.undertow": "redhat",
    "ch.qos.logback": "logback",
    "ch.qos.slf4j": "slf4j",
    "org.yaml": "snakeyaml_project",
    "org.hibernate.validator": "org.hibernate",
    "org.hibernate": "redhat",
    "org.dom4j": "dom4j_project",
    "ant": "apache",
    "commons-": "apache",
    "golang": "golang",
}

# Package aliases
package_alias = {
    "struts2-core": "struts",
    "struts2-rest-plugin": "struts",
    "struts2-showcase": "struts",
    "jackson-databind": "jackson",
    "apache_tomcat": "tomcat",
    "tomcat_native": "tomcat",
    "tomcat_connectors": "tomcat",
    "tomcat_jk_connector": "tomcat",
    "spring-security-core": "spring_security",
    "asciidoctorj": "asciidoctor",
    "postgresql": "postgresql_jdbc_driver",
    "itextpdf": "itext",
    "httpclient": "commons-httpclient",
    "priority": "python_priority_library",
}

# Default ignore list
ignore_directories = [
    ".git",
    ".svn",
    ".mvn",
    ".idea",
    "dist",
    "bin",
    "obj",
    "backup",
    "docs",
    "tests",
    "test",
    "tmp",
    "report",
    "reports",
    "node_modules",
    ".terraform",
    ".serverless",
]
