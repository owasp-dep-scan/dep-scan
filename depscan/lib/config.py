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
vendor_alias = {"org.apache": "apache"}

# Package aliases
package_alias = {"struts2-core": "struts"}
