# Purpose

Generate CSAF vex documents populated with vulnerability results from 
OWASP dep-scan


## Overview

1. Run depscan with the --csaf option.
2. Depscan will check if you already have a csaf.toml file in the target 
   directory before proceeding. 
3. If you do not, the template will be downloaded from our repo and you will 
   be requested to fill it out before running depscan again.
4. You may want to store an extra [copy](csaf.toml) for your reference, as the 
   comments located in the template will not be present after your first 
   CSAF generation.
5. To produce a valid CSAF document, a number of fields must be included in 
   the toml. Some you may choose to set yourself, or we will set them for you.
   Please see the official [CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html) standard for a full explanation of 
   requirements. A copy of the schema is available [here](csaf_json_schema.
   json). See [TOML Requirements](#toml-requirements) for a brief overview.
6. Run depscan with the --csaf option again.
7. This time, a CSAF document will be written to the reports directory that 
   you specified using the --reports-dir option (default behavior creates a 
   reports directory in your current directory).

### The csaf.toml
The first time you run depscan against a specific directory, a csaf.
toml template will be downloaded from our repo and you will be requested to fill 
it out before running depscan again. This is a configuration file used to set 
metadata fields outside the vulnerabilities section.

#### Requirements

In order to produce a valid CSAF, certain sections are required. An overview 
is below, with required components in bold. 
> Note: Where a top level category, such as Notes is not bolded, but one of its 
> members is, that indicates the bolded are only required if the parent category 
> is included, e.g. a notes.note entry must include category and text, but a 
> valid CSAF does not require that any notes be included.:
- **category** (default = csaf_vex)
- **title**
- **publisher**:
  - **name**
  - **category** (enum: coordinator, discoverer, other, translator, user, 
    vendor)
  - **namespace**
  - contact_details
- notes.note
  - **category** (enum: description, details, faq, general, legal_disclaimer, other, summary)
  - **text**
  - audience
  - title
- references.ref
  - **summary**
  - **url**
  - category (enum: self, external)
- product_tree
  - easy_import: As of now, we only support importing a product tree from a 
    json file, the path of which should be specified here. [example](../test/data/product_tree.json)
- distribution
  - text
  - tlp
    - **label**
    - url
  
>Note: Although tracking and all of its components are required, if you do 
      not include them, we will use the current date/time and update the 
      version as appropriate.
- **tracking**
  - **current release date**
  - **initial release date**
  - **version**
  - **id**
  - **status** (enum: draft, final, interim)
- **tracking.revision_history.revision**
  Leave this section alone and depscan will add an initial entry plus
    additional entries any time you run a scan and your tracking status is 
    'final'

>Feel free to preserve all fields on the toml if you may want them later. 
> Entries without content will be omitted.

### Validation
Coming soon! For now, you can validate your generated CSAFs using a [JSON 
schema 
validator](https://www.jsonschemavalidator.net/) and the [csaf 2.0 schema](csaf_json_schema.json).

### Questions? Comments? Suggestions?
Feel free to reach out to us on [discord](https://discord.gg/DCNxzaeUpd) or start a discussion tagging 
@cerrussell on the [OWASP Dep-Scan Repo](https://github.com/owasp-dep-scan/dep-scan).
