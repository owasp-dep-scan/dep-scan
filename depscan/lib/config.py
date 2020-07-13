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
    "org.apache.commons.beanutils": "commons-beanutils",
    "org.apache.commons.collections": "commons-collections",
    "org.apache": "apache",
    "org.apache.solr": "apache_solr",
    "org.apache.solr": "apache_solr_real-time_project",
    "com.fasterxml": "fasterxml",
    "org.bouncycastle": "bouncycastle",
    "org.codehaus.jackson": "codehaus",
    "org.cryptacular": "cryptacular",
    "org.dom4j": "dom4j",
    "org.eclipse": "eclipse",
    "org.hibernate": "hibernate",
    "org.http4s": "http4s",
    "org.infinispan": "infinispan",
    "org.java-websocket": "java-websocket",
    "org.jboss": "jboss",
    "org.jooby": "jooby",
    "org.keycloak": "keycloak",
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
