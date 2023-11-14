# Purpose

Generate CSAF VEX documents populated with vulnerability results from
OWASP dep-scan.

## Overview

1. Run depscan with the --csaf option.
2. Depscan will check if you already have a csaf.toml file in the target
   directory before proceeding.
3. If you do not, the template will be downloaded from our repo and you will
   be requested to fill it out before running depscan again.
4. You may want to store an extra [copy](csaf.toml) for your reference, as the
   comments located in the template will not be present after your first
   CSAF generation.
5. To produce a valid CSAF VEX document, a number of fields must be included in
   the toml. Some you may choose to set yourself, or we will set them for you.
   Please see the official [CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html) standard for a full explanation of
   requirements. A copy of the schema is available [here](csaf_json_schema.
   json). See [TOML Requirements](#toml-requirements) for a brief overview.
6. Run depscan with the --csaf option again.
7. This time, a CSAF VEX document will be written to the reports directory that
   you specified using the --reports-dir option (default behavior creates a
   reports directory in your current directory).

### The csaf.toml

The first time you run depscan with the --csaf option against a specific
directory, a csaf.toml template will be placed in your target directory and you
will be requested to fill it out before running depscan again. This is a
configuration file used to set metadata fields outside the vulnerabilities
section.

#### Requirements

In order to produce a valid CSAF VEX, certain sections are required. An overview
is below, with required components in bold.

> Where a top level category, such as Note is not bolded, but one of its
> members is, that indicates the bolded are only required if the parent category
> is included, e.g. a note entry must include category and text, but a
> valid CSAF does not require that any notes be included.:

| TOML Field        | Subcategories                                                                                   | Comments                                                                                                                                                                                                                                                                                                                                  |
| ----------------- | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **document**      | **category<br>title**                                                                           | default category is csaf*vex<br>category must match regex: `^[^\s\-*\.](.\*[^\s\-_\.])?$`                                                                                                                                                                                                                                                 |
| **publisher**     | **name**<br>**category**<br>**namespace**<br>contact_details                                    | <br>valid categories: coordinator, discoverer, other, translator, user, vendor<br><br>e.g. an email address                                                                                                                                                                                                                               |
| note              | **category**<br>**text**<br>audience<br>title                                                   | valid categories: description, details, faq, general, legal_disclaimer, other, summary<br><br>multiple note entries may be included under additional [note] headings                                                                                                                                                                      |
| reference         | **summary**<br>**url**<br>category                                                              | multiple reference entries may be included under additional [reference] headings<br><br>valid categories: self, external                                                                                                                                                                                                                  |
| distribution      | text<br>tlp.**label**<br>tlp.url                                                                | If tlp is included, label is required<br>valid labels: AMBER, GREEN, RED, WHITE                                                                                                                                                                                                                                                           |
| product_tree      | easy_import                                                                                     | We support importing a product tree from a json file, the path of which should be specified here. If you do not provide this data, we will instead try to import the root component identified by the cdxgen sbom. If neither of these attempts succeeds, the product_tree will be omitted. <br>[example](../test/data/product_tree.json) |
| **tracking**      | **current_release_date**<br/>**initial_release_date**<br/>**version**<br/>**status**<br/>**id** | Please use ISO date formats if entering dates yourself.<br/><br/>valid statuses: draft, final, interim<br/>We will generate an id consisting of date and version if you do not include this, but id is best set by you                                                                                                                    |
| tracking.revision | date<br/>number<br/>summary                                                                     | Leave this section alone. Depscan will add revision entries per final version.                                                                                                                                                                                                                                                            |
| depscan_version   |                                                                                                 | This field is automatically updated for our use to provide backward compatibility if the TOML options change                                                                                                                                                                                                                              |

> Although tracking and all of its components are required, if you do

      not include them, we will use the current date/time and update the
      version as appropriate.

> Feel free to preserve all fields on the toml if you may want them later.
> Entries without content will be omitted.

### Validation

Coming soon! For now, you can validate your generated CSAFs using a [JSON
schema validator](https://www.jsonschemavalidator.net/) and the [csaf 2.0 schema](csaf_json_schema.json).
If you're looking for a cli with this functionality, I've found
check-jsonschema easy to use.
`pip install check-jsonschema`
`python check-jsonschema --schemafile contrib/csaf_json_schema.json 
your_csaf_file`

### Questions? Comments? Suggestions?

Feel free to reach out to us on [discord](https://discord.gg/DCNxzaeUpd) or start a discussion tagging
@cerrussell on the [OWASP Dep-Scan Repo](https://github.com/owasp-dep-scan/dep-scan).
