import json
import logging
import os
import re
from copy import deepcopy
from datetime import datetime
from json import JSONDecodeError

import toml
from vdb.lib import convert_time
from vdb.lib.utils import version_compare

from depscan.lib.logger import LOG
from depscan.lib.utils import get_version

TIME_FMT = "%Y-%m-%dT%H:%M:%S"

CWE_MAP = {
    "CWE-5": "J2EE Misconfiguration: Data Transmission Without Encryption",
    "CWE-6": "J2EE Misconfiguration: Insufficient Session-ID Length",
    "CWE-7": "J2EE Misconfiguration: Missing Custom Error Page",
    "CWE-8": "J2EE Misconfiguration: Entity Bean Declared Remote",
    "CWE-9": "J2EE Misconfiguration: Weak Access Permissions for EJB Methods",
    "CWE-11": "ASP.NET Misconfiguration: Creating Debug Binary",
    "CWE-12": "ASP.NET Misconfiguration: Missing Custom Error Page",
    "CWE-13": "ASP.NET Misconfiguration: Password in Configuration File",
    "CWE-14": "Compiler Removal of Code to Clear Buffers",
    "CWE-15": "External Control of System or Configuration Setting",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory",
    "CWE-23": "Relative Path Traversal",
    "CWE-24": "Path Traversal",
    "CWE-25": "Path Traversal",
    "CWE-26": "Path Traversal",
    "CWE-27": "Path Traversal",
    "CWE-28": "Path Traversal",
    "CWE-29": "Path Traversal",
    "CWE-30": "Path Traversal",
    "CWE-31": "Path Traversal",
    "CWE-32": "Path Traversal",
    "CWE-33": "Path Traversal",
    "CWE-34": "Path Traversal",
    "CWE-35": "Path Traversal",
    "CWE-36": "Absolute Path Traversal",
    "CWE-37": "Path Traversal",
    "CWE-38": "Path Traversal",
    "CWE-39": "Path Traversal",
    "CWE-40": "Path Traversal",
    "CWE-41": "Improper Resolution of Path Equivalence",
    "CWE-42": "Path Equivalence",
    "CWE-43": "Path Equivalence",
    "CWE-44": "Path Equivalence",
    "CWE-45": "Path Equivalence",
    "CWE-46": "Path Equivalence",
    "CWE-47": "Path Equivalence",
    "CWE-48": "Path Equivalence",
    "CWE-49": "Path Equivalence",
    "CWE-50": "Path Equivalence",
    "CWE-51": "Path Equivalence",
    "CWE-52": "Path Equivalence",
    "CWE-53": "Path Equivalence",
    "CWE-54": "Path Equivalence",
    "CWE-55": "Path Equivalence",
    "CWE-56": "Path Equivalence",
    "CWE-57": "Path Equivalence",
    "CWE-58": "Path Equivalence",
    "CWE-59": "Improper Link Resolution Before File Access",
    "CWE-61": "UNIX Symbolic Link",
    "CWE-62": "UNIX Hard Link",
    "CWE-64": "Windows Shortcut Following",
    "CWE-65": "Windows Hard Link",
    "CWE-66": "Improper Handling of File Names that Identify Virtual Resources",
    "CWE-67": "Improper Handling of Windows Device Names",
    "CWE-69": "Improper Handling of Windows ::DATA Alternate Data Stream",
    "CWE-71": "DEPRECATED: Apple .DS_Store",
    "CWE-72": "Improper Handling of Apple HFS+ Alternate Data Stream Path",
    "CWE-73": "External Control of File Name or Path",
    "CWE-74": "Improper Neutralization of Special Elements in Output Used by "
    "a Downstream Component",
    "CWE-75": "Failure to Sanitize Special Elements into a Different Plane",
    "CWE-76": "Improper Neutralization of Equivalent Special Elements",
    "CWE-77": "Improper Neutralization of Special Elements used in a Command",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS "
    "Command",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation",
    "CWE-80": "Improper Neutralization of Script-Related HTML Tags in a Web "
    "Page",
    "CWE-81": "Improper Neutralization of Script in an Error Message Web Page",
    "CWE-82": "Improper Neutralization of Script in Attributes of IMG Tags in "
    "a Web Page",
    "CWE-83": "Improper Neutralization of Script in Attributes in a Web Page",
    "CWE-84": "Improper Neutralization of Encoded URI Schemes in a Web Page",
    "CWE-85": "Doubled Character XSS Manipulations",
    "CWE-86": "Improper Neutralization of Invalid Characters in Identifiers "
    "in Web Pages",
    "CWE-87": "Improper Neutralization of Alternate XSS Syntax",
    "CWE-88": "Improper Neutralization of Argument Delimiters in a Command",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL "
    "Command",
    "CWE-90": "Improper Neutralization of Special Elements used in an LDAP "
    "Query",
    "CWE-91": "XML Injection",
    "CWE-92": "DEPRECATED: Improper Sanitization of Custom Special Characters",
    "CWE-93": "Improper Neutralization of CRLF Sequences",
    "CWE-94": "Improper Control of Generation of Code",
    "CWE-95": "Improper Neutralization of Directives in Dynamically Evaluated "
    "Code",
    "CWE-96": "Improper Neutralization of Directives in Statically Saved Code",
    "CWE-97": "Improper Neutralization of Server-Side Includes",
    "CWE-98": "Improper Control of Filename for Include/Require Statement in "
    "PHP Program",
    "CWE-99": "Improper Control of Resource Identifiers",
    "CWE-102": "Struts: Duplicate Validation Forms",
    "CWE-103": "Struts: Incomplete validate",
    "CWE-104": "Struts: Form Bean Does Not Extend Validation Class",
    "CWE-105": "Struts: Form Field Without Validator",
    "CWE-106": "Struts: Plug-in Framework not in Use",
    "CWE-107": "Struts: Unused Validation Form",
    "CWE-108": "Struts: Unvalidated Action Form",
    "CWE-109": "Struts: Validator Turned Off",
    "CWE-110": "Struts: Validator Without Form Field",
    "CWE-111": "Direct Use of Unsafe JNI",
    "CWE-112": "Missing XML Validation",
    "CWE-113": "Improper Neutralization of CRLF Sequences in HTTP Headers",
    "CWE-114": "Process Control",
    "CWE-115": "Misinterpretation of Input",
    "CWE-116": "Improper Encoding or Escaping of Output",
    "CWE-117": "Improper Output Neutralization for Logs",
    "CWE-118": "Incorrect Access of Indexable Resource",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a "
    "Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-123": "Write-what-where Condition",
    "CWE-124": "Buffer Underwrite",
    "CWE-125": "Out-of-bounds Read",
    "CWE-126": "Buffer Over-read",
    "CWE-127": "Buffer Under-read",
    "CWE-128": "Wrap-around Error",
    "CWE-129": "Improper Validation of Array Index",
    "CWE-130": "Improper Handling of Length Parameter Inconsistency",
    "CWE-131": "Incorrect Calculation of Buffer Size",
    "CWE-132": "DEPRECATED: Miscalculated Null Termination",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-135": "Incorrect Calculation of Multi-Byte String Length",
    "CWE-138": "Improper Neutralization of Special Elements",
    "CWE-140": "Improper Neutralization of Delimiters",
    "CWE-141": "Improper Neutralization of Parameter/Argument Delimiters",
    "CWE-142": "Improper Neutralization of Value Delimiters",
    "CWE-143": "Improper Neutralization of Record Delimiters",
    "CWE-144": "Improper Neutralization of Line Delimiters",
    "CWE-145": "Improper Neutralization of Section Delimiters",
    "CWE-146": "Improper Neutralization of Expression/Command Delimiters",
    "CWE-147": "Improper Neutralization of Input Terminators",
    "CWE-148": "Improper Neutralization of Input Leaders",
    "CWE-149": "Improper Neutralization of Quoting Syntax",
    "CWE-150": "Improper Neutralization of Escape, Meta, or Control Sequences",
    "CWE-151": "Improper Neutralization of Comment Delimiters",
    "CWE-152": "Improper Neutralization of Macro Symbols",
    "CWE-153": "Improper Neutralization of Substitution Characters",
    "CWE-154": "Improper Neutralization of Variable Name Delimiters",
    "CWE-155": "Improper Neutralization of Wildcards or Matching Symbols",
    "CWE-156": "Improper Neutralization of Whitespace",
    "CWE-157": "Failure to Sanitize Paired Delimiters",
    "CWE-158": "Improper Neutralization of Null Byte or NUL Character",
    "CWE-159": "Improper Handling of Invalid Use of Special Elements",
    "CWE-160": "Improper Neutralization of Leading Special Elements",
    "CWE-161": "Improper Neutralization of Multiple Leading Special Elements",
    "CWE-162": "Improper Neutralization of Trailing Special Elements",
    "CWE-163": "Improper Neutralization of Multiple Trailing Special Elements",
    "CWE-164": "Improper Neutralization of Internal Special Elements",
    "CWE-165": "Improper Neutralization of Multiple Internal Special Elements",
    "CWE-166": "Improper Handling of Missing Special Element",
    "CWE-167": "Improper Handling of Additional Special Element",
    "CWE-168": "Improper Handling of Inconsistent Special Elements",
    "CWE-170": "Improper Null Termination",
    "CWE-172": "Encoding Error",
    "CWE-173": "Improper Handling of Alternate Encoding",
    "CWE-174": "Double Decoding of the Same Data",
    "CWE-175": "Improper Handling of Mixed Encoding",
    "CWE-176": "Improper Handling of Unicode Encoding",
    "CWE-177": "Improper Handling of URL Encoding",
    "CWE-178": "Improper Handling of Case Sensitivity",
    "CWE-179": "Incorrect Behavior Order: Early Validation",
    "CWE-180": "Incorrect Behavior Order: Validate Before Canonicalize",
    "CWE-181": "Incorrect Behavior Order: Validate Before Filter",
    "CWE-182": "Collapse of Data into Unsafe Value",
    "CWE-183": "Permissive List of Allowed Inputs",
    "CWE-184": "Incomplete List of Disallowed Inputs",
    "CWE-185": "Incorrect Regular Expression",
    "CWE-186": "Overly Restrictive Regular Expression",
    "CWE-187": "Partial String Comparison",
    "CWE-188": "Reliance on Data/Memory Layout",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-191": "Integer Underflow",
    "CWE-192": "Integer Coercion Error",
    "CWE-193": "Off-by-one Error",
    "CWE-194": "Unexpected Sign Extension",
    "CWE-195": "Signed to Unsigned Conversion Error",
    "CWE-196": "Unsigned to Signed Conversion Error",
    "CWE-197": "Numeric Truncation Error",
    "CWE-198": "Use of Incorrect Byte Ordering",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-201": "Insertion of Sensitive Information Into Sent Data",
    "CWE-202": "Exposure of Sensitive Information Through Data Queries",
    "CWE-203": "Observable Discrepancy",
    "CWE-204": "Observable Response Discrepancy",
    "CWE-205": "Observable Behavioral Discrepancy",
    "CWE-206": "Observable Internal Behavioral Discrepancy",
    "CWE-207": "Observable Behavioral Discrepancy With Equivalent Products",
    "CWE-208": "Observable Timing Discrepancy",
    "CWE-209": "Generation of Error Message Containing Sensitive Information",
    "CWE-210": "Self-generated Error Message Containing Sensitive Information",
    "CWE-211": "Externally-Generated Error Message Containing Sensitive "
    "Information",
    "CWE-212": "Improper Removal of Sensitive Information Before Storage or "
    "Transfer",
    "CWE-213": "Exposure of Sensitive Information Due to Incompatible Policies",
    "CWE-214": "Invocation of Process Using Visible Sensitive Information",
    "CWE-215": "Insertion of Sensitive Information Into Debugging Code",
    "CWE-216": "DEPRECATED: Containment Errors",
    "CWE-217": "DEPRECATED: Failure to Protect Stored Data from Modification",
    "CWE-218": "DEPRECATED: Failure to provide confidentiality for stored data",
    "CWE-219": "Storage of File with Sensitive Data Under Web Root",
    "CWE-220": "Storage of File With Sensitive Data Under FTP Root",
    "CWE-221": "Information Loss or Omission",
    "CWE-222": "Truncation of Security-relevant Information",
    "CWE-223": "Omission of Security-relevant Information",
    "CWE-224": "Obscured Security-relevant Information by Alternate Name",
    "CWE-225": "DEPRECATED: General Information Management Problems",
    "CWE-226": "Sensitive Information in Resource Not Removed Before Reuse",
    "CWE-228": "Improper Handling of Syntactically Invalid Structure",
    "CWE-229": "Improper Handling of Values",
    "CWE-230": "Improper Handling of Missing Values",
    "CWE-231": "Improper Handling of Extra Values",
    "CWE-232": "Improper Handling of Undefined Values",
    "CWE-233": "Improper Handling of Parameters",
    "CWE-234": "Failure to Handle Missing Parameter",
    "CWE-235": "Improper Handling of Extra Parameters",
    "CWE-236": "Improper Handling of Undefined Parameters",
    "CWE-237": "Improper Handling of Structural Elements",
    "CWE-238": "Improper Handling of Incomplete Structural Elements",
    "CWE-239": "Failure to Handle Incomplete Element",
    "CWE-240": "Improper Handling of Inconsistent Structural Elements",
    "CWE-241": "Improper Handling of Unexpected Data Type",
    "CWE-242": "Use of Inherently Dangerous Function",
    "CWE-243": "Creation of chroot Jail Without Changing Working Directory",
    "CWE-244": "Improper Clearing of Heap Memory Before Release",
    "CWE-245": "J2EE Bad Practices: Direct Management of Connections",
    "CWE-246": "J2EE Bad Practices: Direct Use of Sockets",
    "CWE-247": "DEPRECATED: Reliance on DNS Lookups in a Security Decision",
    "CWE-248": "Uncaught Exception",
    "CWE-249": "DEPRECATED: Often Misused: Path Manipulation",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-252": "Unchecked Return Value",
    "CWE-253": "Incorrect Check of Function Return Value",
    "CWE-256": "Plaintext Storage of a Password",
    "CWE-257": "Storing Passwords in a Recoverable Format",
    "CWE-258": "Empty Password in Configuration File",
    "CWE-259": "Use of Hard-coded Password",
    "CWE-260": "Password in Configuration File",
    "CWE-261": "Weak Encoding for Password",
    "CWE-262": "Not Using Password Aging",
    "CWE-263": "Password Aging with Long Expiration",
    "CWE-266": "Incorrect Privilege Assignment",
    "CWE-267": "Privilege Defined With Unsafe Actions",
    "CWE-268": "Privilege Chaining",
    "CWE-269": "Improper Privilege Management",
    "CWE-270": "Privilege Context Switching Error",
    "CWE-271": "Privilege Dropping / Lowering Errors",
    "CWE-272": "Least Privilege Violation",
    "CWE-273": "Improper Check for Dropped Privileges",
    "CWE-274": "Improper Handling of Insufficient Privileges",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-277": "Insecure Inherited Permissions",
    "CWE-278": "Insecure Preserved Inherited Permissions",
    "CWE-279": "Incorrect Execution-Assigned Permissions",
    "CWE-280": "Improper Handling of Insufficient Permissions or Privileges ",
    "CWE-281": "Improper Preservation of Permissions",
    "CWE-282": "Improper Ownership Management",
    "CWE-283": "Unverified Ownership",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-286": "Incorrect User Management",
    "CWE-287": "Improper Authentication",
    "CWE-288": "Authentication Bypass Using an Alternate Path or Channel",
    "CWE-289": "Authentication Bypass by Alternate Name",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-291": "Reliance on IP Address for Authentication",
    "CWE-292": "DEPRECATED: Trusting Self-reported DNS Name",
    "CWE-293": "Using Referer Field for Authentication",
    "CWE-294": "Authentication Bypass by Capture-replay",
    "CWE-295": "Improper Certificate Validation",
    "CWE-296": "Improper Following of a Certificates Chain of Trust",
    "CWE-297": "Improper Validation of Certificate with Host Mismatch",
    "CWE-298": "Improper Validation of Certificate Expiration",
    "CWE-299": "Improper Check for Certificate Revocation",
    "CWE-300": "Channel Accessible by Non-Endpoint",
    "CWE-301": "Reflection Attack in an Authentication Protocol",
    "CWE-302": "Authentication Bypass by Assumed-Immutable Data",
    "CWE-303": "Incorrect Implementation of Authentication Algorithm",
    "CWE-304": "Missing Critical Step in Authentication",
    "CWE-305": "Authentication Bypass by Primary Weakness",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-308": "Use of Single-factor Authentication",
    "CWE-309": "Use of Password System for Primary Authentication",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-313": "Cleartext Storage in a File or on Disk",
    "CWE-314": "Cleartext Storage in the Registry",
    "CWE-315": "Cleartext Storage of Sensitive Information in a Cookie",
    "CWE-316": "Cleartext Storage of Sensitive Information in Memory",
    "CWE-317": "Cleartext Storage of Sensitive Information in GUI",
    "CWE-318": "Cleartext Storage of Sensitive Information in Executable",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-321": "Use of Hard-coded Cryptographic Key",
    "CWE-322": "Key Exchange without Entity Authentication",
    "CWE-323": "Reusing a Nonce, Key Pair in Encryption",
    "CWE-324": "Use of a Key Past its Expiration Date",
    "CWE-325": "Missing Cryptographic Step",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-328": "Use of Weak Hash",
    "CWE-329": "Generation of Predictable IV with CBC Mode",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-331": "Insufficient Entropy",
    "CWE-332": "Insufficient Entropy in PRNG",
    "CWE-333": "Improper Handling of Insufficient Entropy in TRNG",
    "CWE-334": "Small Space of Random Values",
    "CWE-335": "Incorrect Usage of Seeds in Pseudo-Random Number Generator",
    "CWE-336": "Same Seed in Pseudo-Random Number Generator",
    "CWE-337": "Predictable Seed in Pseudo-Random Number Generator",
    "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator",
    "CWE-339": "Small Seed Space in PRNG",
    "CWE-340": "Generation of Predictable Numbers or Identifiers",
    "CWE-341": "Predictable from Observable State",
    "CWE-342": "Predictable Exact Value from Previous Values",
    "CWE-343": "Predictable Value Range from Previous Values",
    "CWE-344": "Use of Invariant Value in Dynamically Changing Context",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-346": "Origin Validation Error",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-348": "Use of Less Trusted Source",
    "CWE-349": "Acceptance of Extraneous Untrusted Data With Trusted Data",
    "CWE-350": "Reliance on Reverse DNS Resolution for a Security-Critical "
    "Action",
    "CWE-351": "Insufficient Type Distinction",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-353": "Missing Support for Integrity Check",
    "CWE-354": "Improper Validation of Integrity Check Value",
    "CWE-356": "Product UI does not Warn User of Unsafe Actions",
    "CWE-357": "Insufficient UI Warning of Dangerous Operations",
    "CWE-358": "Improperly Implemented Security Check for Standard",
    "CWE-359": "Exposure of Private Personal Information to an Unauthorized "
    "Actor",
    "CWE-360": "Trust of System Event Data",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper "
    "Synchronization",
    "CWE-363": "Race Condition Enabling Link Following",
    "CWE-364": "Signal Handler Race Condition",
    "CWE-365": "DEPRECATED: Race Condition in Switch",
    "CWE-366": "Race Condition within a Thread",
    "CWE-367": "Time-of-check Time-of-use",
    "CWE-368": "Context Switching Race Condition",
    "CWE-369": "Divide By Zero",
    "CWE-370": "Missing Check for Certificate Revocation after Initial Check",
    "CWE-372": "Incomplete Internal State Distinction",
    "CWE-373": "DEPRECATED: State Synchronization Error",
    "CWE-374": "Passing Mutable Objects to an Untrusted Method",
    "CWE-375": "Returning a Mutable Object to an Untrusted Caller",
    "CWE-377": "Insecure Temporary File",
    "CWE-378": "Creation of Temporary File With Insecure Permissions",
    "CWE-379": "Creation of Temporary File in Directory with Insecure "
    "Permissions",
    "CWE-382": "J2EE Bad Practices: Use of System.exit",
    "CWE-383": "J2EE Bad Practices: Direct Use of Threads",
    "CWE-384": "Session Fixation",
    "CWE-385": "Covert Timing Channel",
    "CWE-386": "Symbolic Name not Mapping to Correct Object",
    "CWE-390": "Detection of Error Condition Without Action",
    "CWE-391": "Unchecked Error Condition",
    "CWE-392": "Missing Report of Error Condition",
    "CWE-393": "Return of Wrong Status Code",
    "CWE-394": "Unexpected Status Code or Return Value",
    "CWE-395": "Use of NullPointerException Catch to Detect NULL Pointer "
    "Dereference",
    "CWE-396": "Declaration of Catch for Generic Exception",
    "CWE-397": "Declaration of Throws for Generic Exception",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-401": "Missing Release of Memory after Effective Lifetime",
    "CWE-402": "Transmission of Private Resources into a New Sphere",
    "CWE-403": "Exposure of File Descriptor to Unintended Control Sphere",
    "CWE-404": "Improper Resource Shutdown or Release",
    "CWE-405": "Asymmetric Resource Consumption",
    "CWE-406": "Insufficient Control of Network Message Volume",
    "CWE-407": "Inefficient Algorithmic Complexity",
    "CWE-408": "Incorrect Behavior Order: Early Amplification",
    "CWE-409": "Improper Handling of Highly Compressed Data",
    "CWE-410": "Insufficient Resource Pool",
    "CWE-412": "Unrestricted Externally Accessible Lock",
    "CWE-413": "Improper Resource Locking",
    "CWE-414": "Missing Lock Check",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-419": "Unprotected Primary Channel",
    "CWE-420": "Unprotected Alternate Channel",
    "CWE-421": "Race Condition During Access to Alternate Channel",
    "CWE-422": "Unprotected Windows Messaging Channel",
    "CWE-423": "DEPRECATED: Proxied Trusted Channel",
    "CWE-424": "Improper Protection of Alternate Path",
    "CWE-425": "Direct Request",
    "CWE-426": "Untrusted Search Path",
    "CWE-427": "Uncontrolled Search Path Element",
    "CWE-428": "Unquoted Search Path or Element",
    "CWE-430": "Deployment of Wrong Handler",
    "CWE-431": "Missing Handler",
    "CWE-432": "Dangerous Signal Handler not Disabled During Sensitive "
    "Operations",
    "CWE-433": "Unparsed Raw Web Content Delivery",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-435": "Improper Interaction Between Multiple Correctly-Behaving "
    "Entities",
    "CWE-436": "Interpretation Conflict",
    "CWE-437": "Incomplete Model of Endpoint Features",
    "CWE-439": "Behavioral Change in New Version or Environment",
    "CWE-440": "Expected Behavior Violation",
    "CWE-441": "Unintended Proxy or Intermediary",
    "CWE-443": "DEPRECATED: HTTP response splitting",
    "CWE-444": "Inconsistent Interpretation of HTTP Requests",
    "CWE-446": "UI Discrepancy for Security Feature",
    "CWE-447": "Unimplemented or Unsupported Feature in UI",
    "CWE-448": "Obsolete Feature in UI",
    "CWE-449": "The UI Performs the Wrong Action",
    "CWE-450": "Multiple Interpretations of UI Input",
    "CWE-451": "User Interface",
    "CWE-453": "Insecure Default Variable Initialization",
    "CWE-454": "External Initialization of Trusted Variables or Data Stores",
    "CWE-455": "Non-exit on Failed Initialization",
    "CWE-456": "Missing Initialization of a Variable",
    "CWE-457": "Use of Uninitialized Variable",
    "CWE-458": "DEPRECATED: Incorrect Initialization",
    "CWE-459": "Incomplete Cleanup",
    "CWE-460": "Improper Cleanup on Thrown Exception",
    "CWE-462": "Duplicate Key in Associative List",
    "CWE-463": "Deletion of Data Structure Sentinel",
    "CWE-464": "Addition of Data Structure Sentinel",
    "CWE-466": "Return of Pointer Value Outside of Expected Range",
    "CWE-467": "Use of sizeof",
    "CWE-468": "Incorrect Pointer Scaling",
    "CWE-469": "Use of Pointer Subtraction to Determine Size",
    "CWE-470": "Use of Externally-Controlled Input to Select Classes or Code",
    "CWE-471": "Modification of Assumed-Immutable Data",
    "CWE-472": "External Control of Assumed-Immutable Web Parameter",
    "CWE-473": "PHP External Variable Modification",
    "CWE-474": "Use of Function with Inconsistent Implementations",
    "CWE-475": "Undefined Behavior for Input to API",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-477": "Use of Obsolete Function",
    "CWE-478": "Missing Default Case in Multiple Condition Expression",
    "CWE-479": "Signal Handler Use of a Non-reentrant Function",
    "CWE-480": "Use of Incorrect Operator",
    "CWE-481": "Assigning instead of Comparing",
    "CWE-482": "Comparing instead of Assigning",
    "CWE-483": "Incorrect Block Delimitation",
    "CWE-484": "Omitted Break Statement in Switch",
    "CWE-486": "Comparison of Classes by Name",
    "CWE-487": "Reliance on Package-level Scope",
    "CWE-488": "Exposure of Data Element to Wrong Session",
    "CWE-489": "Active Debug Code",
    "CWE-491": "Public cloneable",
    "CWE-492": "Use of Inner Class Containing Sensitive Data",
    "CWE-493": "Critical Public Variable Without Final Modifier",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-495": "Private Data Structure Returned From A Public Method",
    "CWE-496": "Public Data Assigned to Private Array-Typed Field",
    "CWE-497": "Exposure of Sensitive System Information to an Unauthorized "
    "Control Sphere",
    "CWE-498": "Cloneable Class Containing Sensitive Information",
    "CWE-499": "Serializable Class Containing Sensitive Data",
    "CWE-500": "Public Static Field Not Marked Final",
    "CWE-501": "Trust Boundary Violation",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-506": "Embedded Malicious Code",
    "CWE-507": "Trojan Horse",
    "CWE-508": "Non-Replicating Malicious Code",
    "CWE-509": "Replicating Malicious Code",
    "CWE-510": "Trapdoor",
    "CWE-511": "Logic/Time Bomb",
    "CWE-512": "Spyware",
    "CWE-514": "Covert Channel",
    "CWE-515": "Covert Storage Channel",
    "CWE-516": "DEPRECATED: Covert Timing Channel",
    "CWE-520": ".NET Misconfiguration: Use of Impersonation",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-523": "Unprotected Transport of Credentials",
    "CWE-524": "Use of Cache Containing Sensitive Information",
    "CWE-525": "Use of Web Browser Cache Containing Sensitive Information",
    "CWE-526": "Cleartext Storage of Sensitive Information in an Environment "
    "Variable",
    "CWE-527": "Exposure of Version-Control Repository to an Unauthorized "
    "Control Sphere",
    "CWE-528": "Exposure of Core Dump File to an Unauthorized Control Sphere",
    "CWE-529": "Exposure of Access Control List Files to an Unauthorized "
    "Control Sphere",
    "CWE-530": "Exposure of Backup File to an Unauthorized Control Sphere",
    "CWE-531": "Inclusion of Sensitive Information in Test Code",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-533": "DEPRECATED: Information Exposure Through Server Log Files",
    "CWE-534": "DEPRECATED: Information Exposure Through Debug Log Files",
    "CWE-535": "Exposure of Information Through Shell Error Message",
    "CWE-536": "Servlet Runtime Error Message Containing Sensitive Information",
    "CWE-537": "Java Runtime Error Message Containing Sensitive Information",
    "CWE-538": "Insertion of Sensitive Information into Externally-Accessible "
    "File or Directory",
    "CWE-539": "Use of Persistent Cookies Containing Sensitive Information",
    "CWE-540": "Inclusion of Sensitive Information in Source Code",
    "CWE-541": "Inclusion of Sensitive Information in an Include File",
    "CWE-542": "DEPRECATED: Information Exposure Through Cleanup Log Files",
    "CWE-543": "Use of Singleton Pattern Without Synchronization in a "
    "Multithreaded Context",
    "CWE-544": "Missing Standardized Error Handling Mechanism",
    "CWE-545": "DEPRECATED: Use of Dynamic Class Loading",
    "CWE-546": "Suspicious Comment",
    "CWE-547": "Use of Hard-coded, Security-relevant Constants",
    "CWE-548": "Exposure of Information Through Directory Listing",
    "CWE-549": "Missing Password Field Masking",
    "CWE-550": "Server-generated Error Message Containing Sensitive "
    "Information",
    "CWE-551": "Incorrect Behavior Order: Authorization Before Parsing and "
    "Canonicalization",
    "CWE-552": "Files or Directories Accessible to External Parties",
    "CWE-553": "Command Shell in Externally Accessible Directory",
    "CWE-554": "ASP.NET Misconfiguration: Not Using Input Validation Framework",
    "CWE-555": "J2EE Misconfiguration: Plaintext Password in Configuration "
    "File",
    "CWE-556": "ASP.NET Misconfiguration: Use of Identity Impersonation",
    "CWE-558": "Use of getlogin",
    "CWE-560": "Use of umask",
    "CWE-561": "Dead Code",
    "CWE-562": "Return of Stack Variable Address",
    "CWE-563": "Assignment to Variable without Use",
    "CWE-564": "SQL Injection: Hibernate",
    "CWE-565": "Reliance on Cookies without Validation and Integrity Checking",
    "CWE-566": "Authorization Bypass Through User-Controlled SQL Primary Key",
    "CWE-567": "Unsynchronized Access to Shared Data in a Multithreaded "
    "Context",
    "CWE-568": "finalize",
    "CWE-570": "Expression is Always False",
    "CWE-571": "Expression is Always True",
    "CWE-572": "Call to Thread run",
    "CWE-573": "Improper Following of Specification by Caller",
    "CWE-574": "EJB Bad Practices: Use of Synchronization Primitives",
    "CWE-575": "EJB Bad Practices: Use of AWT Swing",
    "CWE-576": "EJB Bad Practices: Use of Java I/O",
    "CWE-577": "EJB Bad Practices: Use of Sockets",
    "CWE-578": "EJB Bad Practices: Use of Class Loader",
    "CWE-579": "J2EE Bad Practices: Non-serializable Object Stored in Session",
    "CWE-580": "clone",
    "CWE-581": "Object Model Violation: Just One of Equals and Hashcode "
    "Defined",
    "CWE-582": "Array Declared Public, Final, and Static",
    "CWE-583": "finalize",
    "CWE-584": "Return Inside Finally Block",
    "CWE-585": "Empty Synchronized Block",
    "CWE-586": "Explicit Call to Finalize",
    "CWE-587": "Assignment of a Fixed Address to a Pointer",
    "CWE-588": "Attempt to Access Child of a Non-structure Pointer",
    "CWE-589": "Call to Non-ubiquitous API",
    "CWE-590": "Free of Memory not on the Heap",
    "CWE-591": "Sensitive Data Storage in Improperly Locked Memory",
    "CWE-592": "DEPRECATED: Authentication Bypass Issues",
    "CWE-593": "Authentication Bypass: OpenSSL CTX Object Modified after SSL "
    "Objects are Created",
    "CWE-594": "J2EE Framework: Saving Unserializable Objects to Disk",
    "CWE-595": "Comparison of Object References Instead of Object Contents",
    "CWE-596": "DEPRECATED: Incorrect Semantic Object Comparison",
    "CWE-597": "Use of Wrong Operator in String Comparison",
    "CWE-598": "Use of GET Request Method With Sensitive Query Strings",
    "CWE-599": "Missing Validation of OpenSSL Certificate",
    "CWE-600": "Uncaught Exception in Servlet ",
    "CWE-601": "URL Redirection to Untrusted Site",
    "CWE-602": "Client-Side Enforcement of Server-Side Security",
    "CWE-603": "Use of Client-Side Authentication",
    "CWE-605": "Multiple Binds to the Same Port",
    "CWE-606": "Unchecked Input for Loop Condition",
    "CWE-607": "Public Static Final Field References Mutable Object",
    "CWE-608": "Struts: Non-private Field in ActionForm Class",
    "CWE-609": "Double-Checked Locking",
    "CWE-610": "Externally Controlled Reference to a Resource in Another "
    "Sphere",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-612": "Improper Authorization of Index Containing Sensitive "
    "Information",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-614": "Sensitive Cookie in HTTPS Session Without Secure Attribute",
    "CWE-615": "Inclusion of Sensitive Information in Source Code Comments",
    "CWE-616": "Incomplete Identification of Uploaded File Variables",
    "CWE-617": "Reachable Assertion",
    "CWE-618": "Exposed Unsafe ActiveX Method",
    "CWE-619": "Dangling Database Cursor",
    "CWE-620": "Unverified Password Change",
    "CWE-621": "Variable Extraction Error",
    "CWE-622": "Improper Validation of Function Hook Arguments",
    "CWE-623": "Unsafe ActiveX Control Marked Safe For Scripting",
    "CWE-624": "Executable Regular Expression Error",
    "CWE-625": "Permissive Regular Expression",
    "CWE-626": "Null Byte Interaction Error",
    "CWE-627": "Dynamic Variable Evaluation",
    "CWE-628": "Function Call with Incorrectly Specified Arguments",
    "CWE-636": "Not Failing Securely",
    "CWE-637": "Unnecessary Complexity in Protection Mechanism",
    "CWE-638": "Not Using Complete Mediation",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-640": "Weak Password Recovery Mechanism for Forgotten Password",
    "CWE-641": "Improper Restriction of Names for Files and Other Resources",
    "CWE-642": "External Control of Critical State Data",
    "CWE-643": "Improper Neutralization of Data within XPath Expressions",
    "CWE-644": "Improper Neutralization of HTTP Headers for Scripting Syntax",
    "CWE-645": "Overly Restrictive Account Lockout Mechanism",
    "CWE-646": "Reliance on File Name or Extension of Externally-Supplied File",
    "CWE-647": "Use of Non-Canonical URL Paths for Authorization Decisions",
    "CWE-648": "Incorrect Use of Privileged APIs",
    "CWE-649": "Reliance on Obfuscation or Encryption of Security-Relevant "
    "Inputs without Integrity Checking",
    "CWE-650": "Trusting HTTP Permission Methods on the Server Side",
    "CWE-651": "Exposure of WSDL File Containing Sensitive Information",
    "CWE-652": "Improper Neutralization of Data within XQuery Expressions",
    "CWE-653": "Improper Isolation or Compartmentalization",
    "CWE-654": "Reliance on a Single Factor in a Security Decision",
    "CWE-655": "Insufficient Psychological Acceptability",
    "CWE-656": "Reliance on Security Through Obscurity",
    "CWE-657": "Violation of Secure Design Principles",
    "CWE-662": "Improper Synchronization",
    "CWE-663": "Use of a Non-reentrant Function in a Concurrent Context",
    "CWE-664": "Improper Control of a Resource Through its Lifetime",
    "CWE-665": "Improper Initialization",
    "CWE-666": "Operation on Resource in Wrong Phase of Lifetime",
    "CWE-667": "Improper Locking",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-669": "Incorrect Resource Transfer Between Spheres",
    "CWE-670": "Always-Incorrect Control Flow Implementation",
    "CWE-671": "Lack of Administrator Control over Security",
    "CWE-672": "Operation on a Resource after Expiration or Release",
    "CWE-673": "External Influence of Sphere Definition",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-675": "Multiple Operations on Resource in Single-Operation Context",
    "CWE-676": "Use of Potentially Dangerous Function",
    "CWE-680": "Integer Overflow to Buffer Overflow",
    "CWE-681": "Incorrect Conversion between Numeric Types",
    "CWE-682": "Incorrect Calculation",
    "CWE-683": "Function Call With Incorrect Order of Arguments",
    "CWE-684": "Incorrect Provision of Specified Functionality",
    "CWE-685": "Function Call With Incorrect Number of Arguments",
    "CWE-686": "Function Call With Incorrect Argument Type",
    "CWE-687": "Function Call With Incorrectly Specified Argument Value",
    "CWE-688": "Function Call With Incorrect Variable or Reference as Argument",
    "CWE-689": "Permission Race Condition During Resource Copy",
    "CWE-690": "Unchecked Return Value to NULL Pointer Dereference",
    "CWE-691": "Insufficient Control Flow Management",
    "CWE-692": "Incomplete Denylist to Cross-Site Scripting",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-694": "Use of Multiple Resources with Duplicate Identifier",
    "CWE-695": "Use of Low-Level Functionality",
    "CWE-696": "Incorrect Behavior Order",
    "CWE-697": "Incorrect Comparison",
    "CWE-698": "Execution After Redirect",
    "CWE-703": "Improper Check or Handling of Exceptional Conditions",
    "CWE-704": "Incorrect Type Conversion or Cast",
    "CWE-705": "Incorrect Control Flow Scoping",
    "CWE-706": "Use of Incorrectly-Resolved Name or Reference",
    "CWE-707": "Improper Neutralization",
    "CWE-708": "Incorrect Ownership Assignment",
    "CWE-710": "Improper Adherence to Coding Standards",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-733": "Compiler Optimization Removal or Modification of "
    "Security-critical Code",
    "CWE-749": "Exposed Dangerous Method or Function",
    "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
    "CWE-755": "Improper Handling of Exceptional Conditions",
    "CWE-756": "Missing Custom Error Page",
    "CWE-757": "Selection of Less-Secure Algorithm During Negotiation",
    "CWE-758": "Reliance on Undefined, Unspecified, or Implementation-Defined "
    "Behavior",
    "CWE-759": "Use of a One-Way Hash without a Salt",
    "CWE-760": "Use of a One-Way Hash with a Predictable Salt",
    "CWE-761": "Free of Pointer not at Start of Buffer",
    "CWE-762": "Mismatched Memory Management Routines",
    "CWE-763": "Release of Invalid Pointer or Reference",
    "CWE-764": "Multiple Locks of a Critical Resource",
    "CWE-765": "Multiple Unlocks of a Critical Resource",
    "CWE-766": "Critical Data Element Declared Public",
    "CWE-767": "Access to Critical Private Variable via Public Method",
    "CWE-768": "Incorrect Short Circuit Evaluation",
    "CWE-769": "DEPRECATED: Uncontrolled File Descriptor Consumption",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-771": "Missing Reference to Active Allocated Resource",
    "CWE-772": "Missing Release of Resource after Effective Lifetime",
    "CWE-773": "Missing Reference to Active File Descriptor or Handle",
    "CWE-774": "Allocation of File Descriptors or Handles Without Limits or "
    "Throttling",
    "CWE-775": "Missing Release of File Descriptor or Handle after Effective "
    "Lifetime",
    "CWE-776": "Improper Restriction of Recursive Entity References in DTDs",
    "CWE-777": "Regular Expression without Anchors",
    "CWE-778": "Insufficient Logging",
    "CWE-779": "Logging of Excessive Data",
    "CWE-780": "Use of RSA Algorithm without OAEP",
    "CWE-781": "Improper Address Validation in IOCTL with METHOD_NEITHER I/O "
    "Control Code",
    "CWE-782": "Exposed IOCTL with Insufficient Access Control",
    "CWE-783": "Operator Precedence Logic Error",
    "CWE-784": "Reliance on Cookies without Validation and Integrity Checking "
    "in a Security Decision",
    "CWE-785": "Use of Path Manipulation Function without Maximum-sized Buffer",
    "CWE-786": "Access of Memory Location Before Start of Buffer",
    "CWE-787": "Out-of-bounds Write",
    "CWE-788": "Access of Memory Location After End of Buffer",
    "CWE-789": "Memory Allocation with Excessive Size Value",
    "CWE-790": "Improper Filtering of Special Elements",
    "CWE-791": "Incomplete Filtering of Special Elements",
    "CWE-792": "Incomplete Filtering of One or More Instances of Special "
    "Elements",
    "CWE-793": "Only Filtering One Instance of a Special Element",
    "CWE-794": "Incomplete Filtering of Multiple Instances of Special Elements",
    "CWE-795": "Only Filtering Special Elements at a Specified Location",
    "CWE-796": "Only Filtering Special Elements Relative to a Marker",
    "CWE-797": "Only Filtering Special Elements at an Absolute Position",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-799": "Improper Control of Interaction Frequency",
    "CWE-804": "Guessable CAPTCHA",
    "CWE-805": "Buffer Access with Incorrect Length Value",
    "CWE-806": "Buffer Access Using Size of Source Buffer",
    "CWE-807": "Reliance on Untrusted Inputs in a Security Decision",
    "CWE-820": "Missing Synchronization",
    "CWE-821": "Incorrect Synchronization",
    "CWE-822": "Untrusted Pointer Dereference",
    "CWE-823": "Use of Out-of-range Pointer Offset",
    "CWE-824": "Access of Uninitialized Pointer",
    "CWE-825": "Expired Pointer Dereference",
    "CWE-826": "Premature Release of Resource During Expected Lifetime",
    "CWE-827": "Improper Control of Document Type Definition",
    "CWE-828": "Signal Handler with Functionality that is not "
    "Asynchronous-Safe",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-830": "Inclusion of Web Functionality from an Untrusted Source",
    "CWE-831": "Signal Handler Function Associated with Multiple Signals",
    "CWE-832": "Unlock of a Resource that is not Locked",
    "CWE-833": "Deadlock",
    "CWE-834": "Excessive Iteration",
    "CWE-835": "Loop with Unreachable Exit Condition",
    "CWE-836": "Use of Password Hash Instead of Password for Authentication",
    "CWE-837": "Improper Enforcement of a Single, Unique Action",
    "CWE-838": "Inappropriate Encoding for Output Context",
    "CWE-839": "Numeric Range Comparison Without Minimum Check",
    "CWE-841": "Improper Enforcement of Behavioral Workflow",
    "CWE-842": "Placement of User into Incorrect Group",
    "CWE-843": "Access of Resource Using Incompatible Type",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-908": "Use of Uninitialized Resource",
    "CWE-909": "Missing Initialization of Resource",
    "CWE-910": "Use of Expired File Descriptor",
    "CWE-911": "Improper Update of Reference Count",
    "CWE-912": "Hidden Functionality",
    "CWE-913": "Improper Control of Dynamically-Managed Code Resources",
    "CWE-914": "Improper Control of Dynamically-Identified Variables",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined "
    "Object Attributes",
    "CWE-916": "Use of Password Hash With Insufficient Computational Effort",
    "CWE-917": "Improper Neutralization of Special Elements used in an "
    "Expression Language Statement",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-920": "Improper Restriction of Power Consumption",
    "CWE-921": "Storage of Sensitive Data in a Mechanism without Access "
    "Control",
    "CWE-922": "Insecure Storage of Sensitive Information",
    "CWE-923": "Improper Restriction of Communication Channel to Intended "
    "Endpoints",
    "CWE-924": "Improper Enforcement of Message Integrity During Transmission "
    "in a Communication Channel",
    "CWE-925": "Improper Verification of Intent by Broadcast Receiver",
    "CWE-926": "Improper Export of Android Application Components",
    "CWE-927": "Use of Implicit Intent for Sensitive Communication",
    "CWE-939": "Improper Authorization in Handler for Custom URL Scheme",
    "CWE-940": "Improper Verification of Source of a Communication Channel",
    "CWE-941": "Incorrectly Specified Destination in a Communication Channel",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-943": "Improper Neutralization of Special Elements in Data Query "
    "Logic",
    "CWE-1004": "Sensitive Cookie Without HttpOnly Flag",
    "CWE-1007": "Insufficient Visual Distinction of Homoglyphs Presented to "
    "User",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
    "CWE-1022": "Use of Web Link to Untrusted Target with window.opener Access",
    "CWE-1023": "Incomplete Comparison with Missing Factors",
    "CWE-1024": "Comparison of Incompatible Types",
    "CWE-1025": "Comparison Using Wrong Factors",
    "CWE-1037": "Processor Optimization Removal or Modification of "
    "Security-critical Code",
    "CWE-1038": "Insecure Automated Optimizations",
    "CWE-1039": "Automated Recognition Mechanism with Inadequate Detection or "
    "Handling of Adversarial Input Perturbations",
    "CWE-1041": "Use of Redundant Code",
    "CWE-1042": "Static Member Data Element outside of a Singleton Class "
    "Element",
    "CWE-1043": "Data Element Aggregating an Excessively Large Number of "
    "Non-Primitive Elements",
    "CWE-1044": "Architecture with Number of Horizontal Layers Outside of "
    "Expected Range",
    "CWE-1045": "Parent Class with a Virtual Destructor and a Child Class "
    "without a Virtual Destructor",
    "CWE-1046": "Creation of Immutable Text Using String Concatenation",
    "CWE-1047": "Modules with Circular Dependencies",
    "CWE-1048": "Invokable Control Element with Large Number of Outward Calls",
    "CWE-1049": "Excessive Data Query Operations in a Large Data Table",
    "CWE-1050": "Excessive Platform Resource Consumption within a Loop",
    "CWE-1051": "Initialization with Hard-Coded Network Resource "
    "Configuration Data",
    "CWE-1052": "Excessive Use of Hard-Coded Literals in Initialization",
    "CWE-1053": "Missing Documentation for Design",
    "CWE-1054": "Invocation of a Control Element at an Unnecessarily Deep "
    "Horizontal Layer",
    "CWE-1055": "Multiple Inheritance from Concrete Classes",
    "CWE-1056": "Invokable Control Element with Variadic Parameters",
    "CWE-1057": "Data Access Operations Outside of Expected Data Manager "
    "Component",
    "CWE-1058": "Invokable Control Element in Multi-Thread Context with "
    "non-Final Static Storable or Member Element",
    "CWE-1059": "Insufficient Technical Documentation",
    "CWE-1060": "Excessive Number of Inefficient Server-Side Data Accesses",
    "CWE-1061": "Insufficient Encapsulation",
    "CWE-1062": "Parent Class with References to Child Class",
    "CWE-1063": "Creation of Class Instance within a Static Code Block",
    "CWE-1064": "Invokable Control Element with Signature Containing an "
    "Excessive Number of Parameters",
    "CWE-1065": "Runtime Resource Management Control Element in a Component "
    "Built to Run on Application Servers",
    "CWE-1066": "Missing Serialization Control Element",
    "CWE-1067": "Excessive Execution of Sequential Searches of Data Resource",
    "CWE-1068": "Inconsistency Between Implementation and Documented Design",
    "CWE-1069": "Empty Exception Block",
    "CWE-1070": "Serializable Data Element Containing non-Serializable Item "
    "Elements",
    "CWE-1071": "Empty Code Block",
    "CWE-1072": "Data Resource Access without Use of Connection Pooling",
    "CWE-1073": "Non-SQL Invokable Control Element with Excessive Number of "
    "Data Resource Accesses",
    "CWE-1074": "Class with Excessively Deep Inheritance",
    "CWE-1075": "Unconditional Control Flow Transfer outside of Switch Block",
    "CWE-1076": "Insufficient Adherence to Expected Conventions",
    "CWE-1077": "Floating Point Comparison with Incorrect Operator",
    "CWE-1078": "Inappropriate Source Code Style or Formatting",
    "CWE-1079": "Parent Class without Virtual Destructor Method",
    "CWE-1080": "Source Code File with Excessive Number of Lines of Code",
    "CWE-1082": "Class Instance Self Destruction Control Element",
    "CWE-1083": "Data Access from Outside Expected Data Manager Component",
    "CWE-1084": "Invokable Control Element with Excessive File or Data Access "
    "Operations",
    "CWE-1085": "Invokable Control Element with Excessive Volume of "
    "Commented-out Code",
    "CWE-1086": "Class with Excessive Number of Child Classes",
    "CWE-1087": "Class with Virtual Method without a Virtual Destructor",
    "CWE-1088": "Synchronous Access of Remote Resource without Timeout",
    "CWE-1089": "Large Data Table with Excessive Number of Indices",
    "CWE-1090": "Method Containing Access of a Member Element from Another "
    "Class",
    "CWE-1091": "Use of Object without Invoking Destructor Method",
    "CWE-1092": "Use of Same Invokable Control Element in Multiple "
    "Architectural Layers",
    "CWE-1093": "Excessively Complex Data Representation",
    "CWE-1094": "Excessive Index Range Scan for a Data Resource",
    "CWE-1095": "Loop Condition Value Update within the Loop",
    "CWE-1096": "Singleton Class Instance Creation without Proper Locking or "
    "Synchronization",
    "CWE-1097": "Persistent Storable Data Element without Associated "
    "Comparison Control Element",
    "CWE-1098": "Data Element containing Pointer Item without Proper Copy "
    "Control Element",
    "CWE-1099": "Inconsistent Naming Conventions for Identifiers",
    "CWE-1100": "Insufficient Isolation of System-Dependent Functions",
    "CWE-1101": "Reliance on Runtime Component in Generated Code",
    "CWE-1102": "Reliance on Machine-Dependent Data Representation",
    "CWE-1103": "Use of Platform-Dependent Third Party Components",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1105": "Insufficient Encapsulation of Machine-Dependent Functionality",
    "CWE-1106": "Insufficient Use of Symbolic Constants",
    "CWE-1107": "Insufficient Isolation of Symbolic Constant Definitions",
    "CWE-1108": "Excessive Reliance on Global Variables",
    "CWE-1109": "Use of Same Variable for Multiple Purposes",
    "CWE-1110": "Incomplete Design Documentation",
    "CWE-1111": "Incomplete I/O Documentation",
    "CWE-1112": "Incomplete Documentation of Program Execution",
    "CWE-1113": "Inappropriate Comment Style",
    "CWE-1114": "Inappropriate Whitespace Style",
    "CWE-1115": "Source Code Element without Standard Prologue",
    "CWE-1116": "Inaccurate Comments",
    "CWE-1117": "Callable with Insufficient Behavioral Summary",
    "CWE-1118": "Insufficient Documentation of Error Handling Techniques",
    "CWE-1119": "Excessive Use of Unconditional Branching",
    "CWE-1120": "Excessive Code Complexity",
    "CWE-1121": "Excessive McCabe Cyclomatic Complexity",
    "CWE-1122": "Excessive Halstead Complexity",
    "CWE-1123": "Excessive Use of Self-Modifying Code",
    "CWE-1124": "Excessively Deep Nesting",
    "CWE-1125": "Excessive Attack Surface",
    "CWE-1126": "Declaration of Variable with Unnecessarily Wide Scope",
    "CWE-1127": "Compilation with Insufficient Warnings or Errors",
    "CWE-1164": "Irrelevant Code",
    "CWE-1173": "Improper Use of Validation Framework",
    "CWE-1174": "ASP.NET Misconfiguration: Improper Model Validation",
    "CWE-1176": "Inefficient CPU Computation",
    "CWE-1177": "Use of Prohibited Code",
    "CWE-1187": "DEPRECATED: Use of Uninitialized Resource",
    "CWE-1188": "Insecure Default Initialization of Resource",
    "CWE-1189": "Improper Isolation of Shared Resources on System-on-a-Chip",
    "CWE-1190": "DMA Device Enabled Too Early in Boot Phase",
    "CWE-1191": "On-Chip Debug and Test Interface With Improper Access Control",
    "CWE-1192": "System-on-Chip",
    "CWE-1193": "Power-On of Untrusted Execution Core Before Enabling Fabric "
    "Access Control",
    "CWE-1204": "Generation of Weak Initialization Vector",
    "CWE-1209": "Failure to Disable Reserved Bits",
    "CWE-1220": "Insufficient Granularity of Access Control",
    "CWE-1221": "Incorrect Register Defaults or Module Parameters",
    "CWE-1222": "Insufficient Granularity of Address Regions Protected by "
    "Register Locks",
    "CWE-1223": "Race Condition for Write-Once Attributes",
    "CWE-1224": "Improper Restriction of Write-Once Bit Fields",
    "CWE-1229": "Creation of Emergent Resource",
    "CWE-1230": "Exposure of Sensitive Information Through Metadata",
    "CWE-1231": "Improper Prevention of Lock Bit Modification",
    "CWE-1232": "Improper Lock Behavior After Power State Transition",
    "CWE-1233": "Security-Sensitive Hardware Controls with Missing Lock Bit "
    "Protection",
    "CWE-1234": "Hardware Internal or Debug Modes Allow Override of Locks",
    "CWE-1235": "Incorrect Use of Autoboxing and Unboxing for Performance "
    "Critical Operations",
    "CWE-1236": "Improper Neutralization of Formula Elements in a CSV File",
    "CWE-1239": "Improper Zeroization of Hardware Register",
    "CWE-1240": "Use of a Cryptographic Primitive with a Risky Implementation",
    "CWE-1241": "Use of Predictable Algorithm in Random Number Generator",
    "CWE-1242": "Inclusion of Undocumented Features or Chicken Bits",
    "CWE-1243": "Sensitive Non-Volatile Information Not Protected During Debug",
    "CWE-1244": "Internal Asset Exposed to Unsafe Debug Access Level or State",
    "CWE-1245": "Improper Finite State Machines",
    "CWE-1246": "Improper Write Handling in Limited-write Non-Volatile "
    "Memories",
    "CWE-1247": "Improper Protection Against Voltage and Clock Glitches",
    "CWE-1248": "Semiconductor Defects in Hardware Logic with "
    "Security-Sensitive Implications",
    "CWE-1249": "Application-Level Admin Tool with Inconsistent View of "
    "Underlying Operating System",
    "CWE-1250": "Improper Preservation of Consistency Between Independent "
    "Representations of Shared State",
    "CWE-1251": "Mirrored Regions with Different Values",
    "CWE-1252": "CPU Hardware Not Configured to Support Exclusivity of Write "
    "and Execute Operations",
    "CWE-1253": "Incorrect Selection of Fuse Values",
    "CWE-1254": "Incorrect Comparison Logic Granularity",
    "CWE-1255": "Comparison Logic is Vulnerable to Power Side-Channel Attacks",
    "CWE-1256": "Improper Restriction of Software Interfaces to Hardware "
    "Features",
    "CWE-1257": "Improper Access Control Applied to Mirrored or Aliased "
    "Memory Regions",
    "CWE-1258": "Exposure of Sensitive System Information Due to Uncleared "
    "Debug Information",
    "CWE-1259": "Improper Restriction of Security Token Assignment",
    "CWE-1260": "Improper Handling of Overlap Between Protected Memory Ranges",
    "CWE-1261": "Improper Handling of Single Event Upsets",
    "CWE-1262": "Improper Access Control for Register Interface",
    "CWE-1263": "Improper Physical Access Control",
    "CWE-1264": "Hardware Logic with Insecure De-Synchronization between "
    "Control and Data Channels",
    "CWE-1265": "Unintended Reentrant Invocation of Non-reentrant Code Via "
    "Nested Calls",
    "CWE-1266": "Improper Scrubbing of Sensitive Data from Decommissioned "
    "Device",
    "CWE-1267": "Policy Uses Obsolete Encoding",
    "CWE-1268": "Policy Privileges are not Assigned Consistently Between "
    "Control and Data Agents",
    "CWE-1269": "Product Released in Non-Release Configuration",
    "CWE-1270": "Generation of Incorrect Security Tokens",
    "CWE-1271": "Uninitialized Value on Reset for Registers Holding Security "
    "Settings",
    "CWE-1272": "Sensitive Information Uncleared Before Debug/Power State "
    "Transition",
    "CWE-1273": "Device Unlock Credential Sharing",
    "CWE-1274": "Improper Access Control for Volatile Memory Containing Boot "
    "Code",
    "CWE-1275": "Sensitive Cookie with Improper SameSite Attribute",
    "CWE-1276": "Hardware Child Block Incorrectly Connected to Parent System",
    "CWE-1277": "Firmware Not Updateable",
    "CWE-1278": "Missing Protection Against Hardware Reverse Engineering "
    "Using Integrated Circuit",
    "CWE-1279": "Cryptographic Operations are run Before Supporting Units are "
    "Ready",
    "CWE-1280": "Access Control Check Implemented After Asset is Accessed",
    "CWE-1281": "Sequence of Processor Instructions Leads to Unexpected "
    "Behavior",
    "CWE-1282": "Assumed-Immutable Data is Stored in Writable Memory",
    "CWE-1283": "Mutable Attestation or Measurement Reporting Data",
    "CWE-1284": "Improper Validation of Specified Quantity in Input",
    "CWE-1285": "Improper Validation of Specified Index, Position, or Offset "
    "in Input",
    "CWE-1286": "Improper Validation of Syntactic Correctness of Input",
    "CWE-1287": "Improper Validation of Specified Type of Input",
    "CWE-1288": "Improper Validation of Consistency within Input",
    "CWE-1289": "Improper Validation of Unsafe Equivalence in Input",
    "CWE-1290": "Incorrect Decoding of Security Identifiers ",
    "CWE-1291": "Public Key Re-Use for Signing both Debug and Production Code",
    "CWE-1292": "Incorrect Conversion of Security Identifiers",
    "CWE-1293": "Missing Source Correlation of Multiple Independent Data",
    "CWE-1294": "Insecure Security Identifier Mechanism",
    "CWE-1295": "Debug Messages Revealing Unnecessary Information",
    "CWE-1296": "Incorrect Chaining or Granularity of Debug Components",
    "CWE-1297": "Unprotected Confidential Information on Device is Accessible "
    "by OSAT Vendors",
    "CWE-1298": "Hardware Logic Contains Race Conditions",
    "CWE-1299": "Missing Protection Mechanism for Alternate Hardware Interface",
    "CWE-1300": "Improper Protection of Physical Side Channels",
    "CWE-1301": "Insufficient or Incomplete Data Removal within Hardware "
    "Component",
    "CWE-1302": "Missing Security Identifier",
    "CWE-1303": "Non-Transparent Sharing of Microarchitectural Resources",
    "CWE-1304": "Improperly Preserved Integrity of Hardware Configuration "
    "State During a Power Save/Restore Operation",
    "CWE-1310": "Missing Ability to Patch ROM Code",
    "CWE-1311": "Improper Translation of Security Attributes by Fabric Bridge",
    "CWE-1312": "Missing Protection for Mirrored Regions in On-Chip Fabric "
    "Firewall",
    "CWE-1313": "Hardware Allows Activation of Test or Debug Logic at Runtime",
    "CWE-1314": "Missing Write Protection for Parametric Data Values",
    "CWE-1315": "Improper Setting of Bus Controlling Capability in Fabric "
    "End-point",
    "CWE-1316": "Fabric-Address Map Allows Programming of Unwarranted "
    "Overlaps of Protected and Unprotected Ranges",
    "CWE-1317": "Improper Access Control in Fabric Bridge",
    "CWE-1318": "Missing Support for Security Features in On-chip Fabrics or "
    "Buses",
    "CWE-1319": "Improper Protection against Electromagnetic Fault Injection",
    "CWE-1320": "Improper Protection for Outbound Error Messages and Alert "
    "Signals",
    "CWE-1321": "Improperly Controlled Modification of Object Prototype "
    "Attributes",
    "CWE-1322": "Use of Blocking Code in Single-threaded, Non-blocking Context",
    "CWE-1323": "Improper Management of Sensitive Trace Data",
    "CWE-1324": "DEPRECATED: Sensitive Information Accessible by Physical "
    "Probing of JTAG Interface",
    "CWE-1325": "Improperly Controlled Sequential Memory Allocation",
    "CWE-1326": "Missing Immutable Root of Trust in Hardware",
    "CWE-1327": "Binding to an Unrestricted IP Address",
    "CWE-1328": "Security Version Number Mutable to Older Versions",
    "CWE-1329": "Reliance on Component That is Not Updateable",
    "CWE-1330": "Remanent Data Readable after Memory Erase",
    "CWE-1331": "Improper Isolation of Shared Resources in Network On Chip",
    "CWE-1332": "Improper Handling of Faults that Lead to Instruction Skips",
    "CWE-1333": "Inefficient Regular Expression Complexity",
    "CWE-1334": "Unauthorized Error Injection Can Degrade Hardware Redundancy",
    "CWE-1335": "Incorrect Bitwise Shift of Integer",
    "CWE-1336": "Improper Neutralization of Special Elements Used in a "
    "Template Engine",
    "CWE-1338": "Improper Protections Against Hardware Overheating",
    "CWE-1339": "Insufficient Precision or Accuracy of a Real Number",
    "CWE-1341": "Multiple Releases of Same Resource or Handle",
    "CWE-1342": "Information Exposure through Microarchitectural State after "
    "Transient Execution",
    "CWE-1351": "Improper Handling of Hardware Behavior in Exceptionally Cold "
    "Environments",
    "CWE-1357": "Reliance on Insufficiently Trustworthy Component",
    "CWE-1384": "Improper Handling of Physical or Environmental Conditions",
    "CWE-1385": "Missing Origin Validation in WebSockets",
    "CWE-1386": "Insecure Operation on Windows Junction / Mount Point",
    "CWE-1389": "Incorrect Parsing of Numbers with Different Radices",
    "CWE-1390": "Weak Authentication",
    "CWE-1391": "Use of Weak Credentials",
    "CWE-1392": "Use of Default Credentials",
    "CWE-1393": "Use of Default Password",
    "CWE-1394": "Use of Default Cryptographic Key",
    "CWE-1395": "Dependency on Vulnerable Third-Party Component",
}

TOML_TEMPLATE = {
    "depscan_version": get_version(),
    "note": [
        {"audience": "", "category": "", "text": "", "title": ""},
    ],
    "reference": [
        {"category": "", "summary": "", "url": ""},
        {"category": "", "summary": "", "url": ""},
    ],
    "distribution": {"label": "", "text": "", "url": ""},
    "document": {"category": "csaf_vex", "title": "Your Title"},
    "product_tree": {"easy_import": ""},
    "publisher": {
        "category": "vendor",
        "contact_details": "vendor@mcvendorson.com",
        "name": "Vendor McVendorson",
        "namespace": "https://appthreat.com",
    },
    "tracking": {
        "current_release_date": "",
        "id": "",
        "initial_release_date": "",
        "status": "draft",
        "version": "",
        "revision_history": [{"date": "", "number": "", "summary": ""}],
    },
}

ref_map = {
    r"(?P<org>[^\s./]+).(?:com|org)/(?:[\S]+)?/(?P<id>("
    r"?:ghsa|ntap|rhsa|rhba|zdi|dsa|cisco|intel)-?[\w\d\-:]+)": "Advisory",
    r"cve-[0-9]{4,}-[0-9]{4,}$": "CVE Record",
    r"(?<=bugzilla.)\S+(?=.\w{3}/show_bug.cgi\?)": "Bugzilla",
    r"github.com/[\w\-.]+/[\w\-.]+/pull/\d+": "GitHub Pull Request",
    r"github.com/[\w\-.]+/[\w\-.]+/release": "GitHub Repository Release",
    r"(github|bitbucket|chromium)(?:.com|.org)/([\w\-.]+)/([\w\-.]+)/issues/("
    r"?:detail\?id=)?(\d+)": "Issue",
    r"github.com/[\w\-.]+/[\w\-.]+/blob": "GitHub Blob Reference",
    r"github.com/[\w\-.]+/[\w\-.]+/commit": "GitHub Commit",
    r"github.com/[\w\-.]+/[\w\-.]+/?$": "GitHub Repository",
    "gist.github.com": "GitHub Gist",
    r"github.com/": "GitHub Other",
    "npmjs.com/advisories/": "NPM Advisory",
    r"npmjs.com/package/@?\w+/?\w+": "NPM Package Page",
    "oracle.com/security-alerts": "Oracle Security Alert",
    "security.snyk.io/vuln|https://snyk.io/vuln/": "Snyk Vulnerability "
    "Database Entry",
    "security.gentoo.org/glsa": "Advisory",
    r"usn.ubuntu.com/[\d\-]+|ubuntu.com/security/notices/USN\-[\d\-]+":
        "Ubuntu Security Notice",
    r"lists.[\w\-]+.org/[\S]+announce": "Mailing List Announcement",
    r"lists.[\w\-]+.org/": "Mailing List Other",
    "blog": "Blog Post",
    r"bitbucket.org/[^\s/]+/[^\s/]+/?(?!.)": "Bitbucket Repository",
    r"bitbucket.org/[^\s/]+/[^\s/]+/commits": "Bitbucket Commit",
    r"bitbucket.org/[^\s/]+/[^\s/]+/issues/\d+(/)?": "Bitbucket Issue",
    r"bitbucket.org/[^\s/]+/[^\s/]+/wiki/": "Bitbucket Wiki Entry",
    r"https://vuldb.com/\?id.\d+": "VulDB Entry",
}
sorted_ref_map = dict(
    sorted(ref_map.items(), key=lambda x: len(x[0]), reverse=True)
)

compiled_patterns = {
    re.compile(pattern, re.IGNORECASE): value
    for pattern, value in sorted_ref_map.items()
}


class CsafOccurence:
    def __init__(self, res):
        self.cve = res["id"]
        [self.cwe, self.notes] = parse_cwe(res["problem_type"])
        self.score = res["cvss_score"]
        self.cvss_v3 = parse_cvss(res)
        self.package_issue = res["package_issue"]
        [
            self.pkg,
            self.product_status,
            self.vrange,
            self.search_string,
        ] = get_product_status(res["package_issue"], res["matched_by"])
        self.description = (
            res["short_description"]
            .replace("\\n", " ")
            .replace("\\t", " ")
            .replace("\n", " ")
            .replace("\t", " ")
        )
        self.references = res["related_urls"]
        self.type = (res["type"],)
        self.severity = res["severity"]
        self.orig_date = res["source_orig_time"] or None
        self.update_date = res["source_update_time"] or None

    def to_dict(self):
        vuln = {}
        if self.cve.startswith("CVE"):
            vuln["cve"] = self.cve
        vuln["cwe"] = self.cwe
        vuln["discovery_date"] = str(self.orig_date) or str(self.update_date)
        vuln["product_status"] = self.product_status
        [ids, vuln["references"]] = format_references(self.references)
        vuln["ids"] = ids
        vuln["scores"] = [{"cvss_v3": self.cvss_v3, "products": [self.pkg]}]
        self.notes.append(
            {
                "category": "general",
                "text": self.description,
                "details": "Vulnerability Description",
            }
        )
        vuln["notes"] = self.notes
        return vuln


def get_product_status(issue, matched_by):
    """
    Generates the product status based on the given response and package.

    Args:
        issue (dict): The response dictionary of information about the product.
        matched_by (str): The location data

    Returns: dict: A dictionary containing the product status. The keys
    represent different statuses, while the values represent the corresponding
    locations. If the product has a fixed location, the key "fixed" will be
    present with the fixed location as its value. If the product has an affected
    location, the key "known_affected" will be present with the affected
    location as its value.

    """
    product_status = {}
    pkg = matched_by.split("|")
    version_range = None
    search_string = None
    if len(pkg) == 3:
        pkg = matched_by.split("|")[1]
        search_string = pkg
    elif len(pkg) == 4:
        pkg = matched_by.split("|")[2]
        search_string = f"{matched_by.split('|')[1]}/{pkg}"
    if issue.get("fixed_location"):
        product_status["fixed"] = [f"{pkg}:{issue.get('fixed_location')}"]
    if issue.get("affected_location"):
        try:
            loc_dict = issue.get("affected_location")
            version_range = loc_dict.get("version")
            product_status["known_affected"] = [
                f'{loc_dict.get("package")}:{version_range}'
            ]
        except json.JSONDecodeError:
            logging.warning("Invalid JSON string for affected_location")
    return pkg, product_status, version_range, search_string


def parse_cwe(cwe):
    fmt_cwe = None
    new_notes = []

    if not cwe or cwe in ["UNKNOWN", [], "[]"]:
        return fmt_cwe, new_notes

    cwe_ids = re.findall(r"CWE-[1-9]\d{0,5}", cwe)
    for i, cweid in enumerate(cwe_ids):
        cwe_name = CWE_MAP.get(cweid, "UNABLE TO LOCATE CWE NAME")
        if not cwe_name:
            LOG.warning(
                "We couldn't locate the name of the CWE with the following "
                "id: %s. Help us out by reporting the id at "
                "https://github.com/owasp-dep-scan/dep-scan/issues.",
                cweid,
            )
        if i == 0:
            fmt_cwe = {
                "id": cweid,
                "name": cwe_name,
            }
        # CSAF 2.0 only allows a single CWE per vulnerability, so we add
        # any additional CWEs to a note entry.
        else:
            new_notes.append(
                {
                    "title": f"Additional CWE: {cweid}",
                    "audience": "developers",
                    "category": "other",
                    "text": cwe_name,
                }
            )

    return fmt_cwe, new_notes


def parse_cvss(res):
    """
    Parses the CVSS information from the given response.

    Parameters:
        res (dict): The response containing the CVSS information.

    Returns:
        dict or None: The parsed CVSS information as a dictionary, or None if
        the CVSS vector string is empty as it is required for cvss v3.
            The dictionary contains the following keys:
                - baseScore (float): The base score of the CVSS.
                - attackVector (str): The attack vector of the CVSS.
                - privilegesRequired (str): Privileges required for the CVSS.
                - userInteraction (str): User interaction required for the CVSS.
                - scope (str): The scope of the CVSS.
                - impactScore (str): The impact score of the CVSS.
                - baseSeverity (str): The base severity of the CVSS.
                - version (str): The version of the CVSS.
                - vectorString (str): The vector string of the CVSS.
            If the vector string or base score are missing, or the CVSS
            version is not 3.0 or 3.1, None is returned.
    """

    # baseScore, vectorString, and version are required for a valid score
    cvss_v3 = res.get("cvss_v3")
    if (
            not cvss_v3
            or not (vector_string := cvss_v3.get("vector_string"))
            or not (version := re.findall(r"3.0|3.1", cvss_v3.get("vector_string", "")))
            or not (base_score := cvss_v3.get("base_score"))
    ):
        return None
    version = version[0]
    return {
        "baseScore": base_score,
        "attackVector": cvss_v3.get("attack_vector"),
        "privilegesRequired": cvss_v3.get("privileges_required"),
        "userInteraction": cvss_v3.get("user_interaction"),
        "scope": cvss_v3.get("scope"),
        "baseSeverity": res.get("severity"),
        "version": version,
        "vectorString": vector_string,
    }


def format_references(ref):
    """
    Formats the given references.

    Args:
        ref (list): A list of references.

    Returns:
        list: A list of dictionaries with the formatted references.
    """
    fmt_refs = [{"summary": get_ref_summary(r), "url": r} for r in ref]
    ids = []
    issues_regex = re.compile(
        r"(?P<host>github|bitbucket|chromium)(?:.com|.org)/(?P<owner>["
        r"\w\-.]+)/(?P<repo>[\w\-.]+)/issues/(?:detail\?id=)?(?P<id>\d+)",
        re.IGNORECASE,
    )
    advisory_regex = re.compile(
        r"(?P<org>[^\s/.]+).(?:com|org)/(?:\S+/)*/?(?P<id>[\w\-:]+)",
        re.IGNORECASE,
    )
    bugzilla_regex = re.compile(
        r"(?<=bugzilla.)(?P<owner>\S+)\.\w{3}/show_bug.cgi\?id=(?P<id>" r"\S+)",
        re.IGNORECASE,
    )
    usn_regex = re.compile(
        r"(?<=usn.ubuntu.com/)[\d\-]+|(?<=ubuntu.com/security/notices/USN-)["
        r"\d\-]+",
        re.IGNORECASE,
    )
    id_types = ["Advisory", "Issue", "Ubuntu Security Notice", "Bugzilla"]
    parse = [i for i in fmt_refs if i.get("summary") in id_types]
    refs = [i for i in fmt_refs if i.get("summary") not in id_types]
    for reference in parse:
        url = reference["url"]
        summary = reference["summary"]
        if summary == "Advisory":
            url = url.replace("glsa/", "glsa-")
            if adv := re.search(advisory_regex, url):
                system_name = (
                    (adv["org"].capitalize() + " Advisory")
                    .replace("Redhat", "Red Hat")
                    .replace("Zerodayinitiative", "Zero Day Initiative")
                    .replace("Github", "GitHub")
                    .replace("Netapp", "NetApp")
                )
                ids.append({"system_name": system_name, "text": adv["id"]})
                summary = system_name
        elif issue := re.search(issues_regex, url):
            summary = (
                issue["host"].capitalize().replace("Github", "GitHub")
                + " Issue"
            )
            ids.append(
                {
                    "system_name": summary
                    + (
                        f" [{issue['owner']}/{issue['repo']}]"
                        if issue["owner"] != "p"
                        else f" [{issue['repo']}]"
                    ),
                    "text": issue["id"],
                }
            )
        elif bugzilla := re.search(bugzilla_regex, url):
            system_name = f"{bugzilla['owner'].capitalize()} Bugzilla"
            system_name = system_name.replace("Redhat", "Red Hat")
            ids.append(
                {"system_name": f"{system_name} ID", "text": bugzilla["id"]}
            )
            summary = system_name
        elif usn := re.search(usn_regex, url):
            ids.append({"system_name": summary, "text": f"USN-{usn[0]}"})
        refs.append({"summary": summary, "url": url})
    new_ids = {(idx["system_name"], idx["text"]) for idx in ids}
    ids = [{"system_name": idx[0], "text": idx[1]} for idx in new_ids]
    ids = sorted(ids, key=lambda x: x["text"])
    return ids, refs


def get_ref_summary(url):
    """
    Returns the summary string associated with a given URL.

    Parameters:
        url (str): The URL to match against the patterns in the REF_MAP.

    Returns:
        str: The summary string corresponding to the matched pattern in REF_MAP.
             If no match is found, an exception is raised.
    """
    if type(url) is not str:
        raise TypeError("url must be a string")

    return next(
        (
            value
            for pattern, value in compiled_patterns.items()
            if pattern.search(url)
        ),
        "Other",
    )


def parse_revision_history(tracking):
    """
    Parses the revision history of a tracking object.

    Args:
        tracking (dict): The tracking object containing the revision history.

    Returns:
        dict: The updated tracking object with the parsed revision history.
    """
    hx = deepcopy(tracking.get("revision_history")) or []
    if not hx and (tracking.get("version")) != "1":
        LOG.warning("Revision history is empty. Correcting the version number.")
        tracking["version"] = 1

    elif hx and (len(hx) > 0):
        hx = cleanup_list(hx)
        if tracking.get("status") == "final" and int(
            tracking.get("version", 1)
        ) > (len(hx) + 1):
            LOG.warning(
                "Revision history is inconsistent with the version "
                "number. Correcting the version number."
            )
            tracking["version"] = int(len(hx) + 1)
    status = tracking.get("status")
    if not status or len(status) == 0:
        status = "draft"
    dt = datetime.now().strftime(TIME_FMT)
    tracking = cleanup_dict(tracking)
    # Format dates
    try:
        tracking["initial_release_date"] = (
            convert_time(
                tracking.get(
                    "initial_release_date",
                    tracking.get("current_release_date", dt),
                )
            )
        ).strftime(TIME_FMT)
        tracking["current_release_date"] = (
            convert_time(
                tracking.get(
                    "current_release_date", tracking.get("initial_release_date")
                )
            )
        ).strftime(TIME_FMT)
    except AttributeError:
        LOG.warning("Your dates don't appear to be in ISO format.")
    if status == "final" and (not hx or len(hx) == 0):
        choose_date = max(
            tracking.get("initial_release_date"),
            tracking.get("current_release_date"),
        )
        hx.append(
            {
                "date": choose_date,
                "number": "1",
                "summary": "Initial",
            }
        )
        tracking["current_release_date"] = choose_date
        tracking["initial_release_date"] = choose_date
    elif status == "final":
        hx = sorted(hx, key=lambda x: x["number"])
        tracking["initial_release_date"] = hx[0]["date"]
        if tracking["current_release_date"] == hx[-1]["date"]:
            tracking["current_release_date"] = dt
        hx.append(
            {
                "date": tracking["current_release_date"],
                "number": str(len(hx) + 1),
                "summary": "Update",
            }
        )
    if len(hx) > 0:
        tracking["version"] = str(
            max(int(tracking.get("version", 0)), int(hx[-1]["number"]))
        )
    else:
        tracking["version"] = "1"
    if not tracking.get("id") or len(tracking.get("id")) == 0:
        LOG.info("No tracking id, generating one.")
        tracking["id"] = f"{dt}_v{tracking['version']}"
    if (tracking["initial_release_date"]) > (tracking["current_release_date"]):
        LOG.warning(
            "Your initial release date is later than the current release date."
        )
    hx = sorted(hx, key=lambda x: x["number"])

    tracking["revision_history"] = hx
    tracking["status"] = status
    return tracking


def import_product_tree(tree):
    """
    Set the product tree by loading it from a file.

    Parameters:
        tree (dict): The dictionary representing the tree.

    Returns:
        dict: The product tree loaded from the file, or None if file is empty.
    """
    product_tree = None
    if len(tree["easy_import"]) > 0:
        try:
            with open(tree["easy_import"], "r", encoding="utf-8") as f:
                product_tree = json.load(f)
        except JSONDecodeError:
            LOG.warning(
                "Unable to load product tree file. Please verify that your "
                "product tree is a valid json file. Visit "
                "https://github.com/owasp-dep-scan/dep-scan/blob/master/test"
                "/data/product_tree.json for an example."
            )
        except FileNotFoundError:
            LOG.warning(
                "Cannot locate product tree at %s. Please verify you "
                "have entered the correct filepath in your csaf.toml.",
                tree["easy_import"],
            )
    return product_tree


def parse_toml(metadata):
    """
    Parses the given metadata in TOML format and generates an output dictionary.

    Args:
        metadata (dict): A dictionary containing the metadata in TOML format.

    Returns:
        dict: The generated output dictionary.

    Raises:
        Exception: If the 'product_tree' entry is missing in the TOML file.
        Exception: If the 'initial_release_date' is later than the
        'current_release_date'.
    """
    tracking = parse_revision_history(metadata.get("tracking"))
    refs = []
    [refs.append(v) for v in metadata.get("reference")]
    notes = []
    [notes.append(v) for v in metadata.get("note")]
    product_tree = import_product_tree(metadata["product_tree"])
    return {
        "document": {
            "aggregate_severity": {},
            "category": metadata["document"]["category"],
            "title": metadata["document"]["title"] or "Test",
            "csaf_version": "2.0",
            "distribution": metadata.get("distribution"),
            "lang": "en",
            "notes": notes,
            "publisher": {
                "category": metadata["publisher"]["category"],
                "contact_details": metadata["publisher"].get("contact_details"),
                "name": metadata["publisher"]["name"],
                "namespace": metadata["publisher"]["namespace"],
            },
            "references": refs,
            "tracking": tracking,
        },
        "product_tree": product_tree,
        "vulnerabilities": [],
    }


def toml_compatibility(metadata):
    """
    Applies any changes to the formatting of the TOML after a depscan
    minor or patch update
    """
    # Removed compatibility for 5.0.0 release

    # The 4.3.0 TOML referenced revision_history as revision
    # if metadata["depscan_version"] < "4.3.1":
    #     metadata["tracking"]["revision_history"] = metadata["tracking"].get(
    #         "revision"
    #     )
    # if metadata["tracking"].get("revision"):
    #     del metadata["tracking"]["revision"]

    return metadata


def export_csaf(
    results,
    src_dir,
    reports_dir,
    vdr_file,
    direct_purls,
    reached_purls,
):
    """
    Generates a CSAF JSON template from the given results.

    Parameters:
        results (list): Raw results from scan
        src_dir (str): The source directory.
        reports_dir (str): The reports directory.
        vdr_file (str): The BOM file path
        direct_purls (dict): Package URLs with direct usages
        reached_purls (dict): Package URLs with reachable flows

    Returns:
        None
    """
    toml_file_path = os.getenv(
        "DEPSCAN_CSAF_TEMPLATE", os.path.join(src_dir, "csaf.toml")
    )
    metadata = import_csaf_toml(toml_file_path)
    metadata = toml_compatibility(metadata)
    template = parse_toml(metadata)
    new_results = add_vulnerabilities(
        template, results, direct_purls, reached_purls
    )
    new_results = cleanup_dict(new_results)
    [new_results, metadata] = verify_components_present(
        new_results, metadata, vdr_file
    )

    outfile = os.path.join(
        reports_dir,
        f"csaf_v{new_results['document']['tracking']['version']}.json",
    )
    json.dump(new_results, open(outfile, "w", encoding="utf-8"), indent=4)
    LOG.info("CSAF report written to %s", outfile)
    write_toml(toml_file_path, metadata)


def import_csaf_toml(toml_file_path):
    """
    Reads the contents of the "csaf.toml" file, parses it as TOML, and converts
    it to JSON format.

    Returns:
        dict: A dictionary containing the parsed contents of the csaf.toml

    Raises:
        TOMLDecodeError: If the TOML file contains duplicate keys or is invalid.
    """
    try:
        with open(toml_file_path, "r", encoding="utf-8") as f:
            try:
                toml_data = toml.load(f)
            except toml.TomlDecodeError:
                LOG.error(
                    "Invalid TOML. Please make sure you do not have any "
                    "duplicate keys and that any filepaths are properly escaped"
                    "if using Windows."
                )
                exit(1)
    except FileNotFoundError:
        write_toml(toml_file_path)
        return import_csaf_toml(toml_file_path)

    return toml_compatibility(toml_data)


def write_toml(toml_file_path, metadata=None):
    """
    Retrieves the TOML template file from the given URL and saves it to the
    specified file name.

    Parameters:
        toml_file_path (str): The filepath to save the TOML template to.

        metadata (dict): A dictionary containing the TOML metadata.

    """
    if not metadata:
        metadata = TOML_TEMPLATE
    metadata["depscan_version"] = get_version()
    with open(toml_file_path, "w", encoding="utf-8") as f:
        toml.dump(metadata, f)
    LOG.info("The csaf.toml has been updated at %s", toml_file_path)


def cleanup_list(d):
    """
    Generate a function comment for the given function body in a markdown code
    block with the correct language syntax.

    Args:
        d (list): A list of dictionaries and strings.

    Returns:
        list: A new list containing cleaned up entries from the input list.
    """
    new_lst = []
    for dl in d:
        if isinstance(dl, dict):
            if entry := cleanup_dict(dl):
                new_lst.append(entry)
        elif isinstance(dl, str):
            new_lst.append(dl)
    return new_lst


def cleanup_dict(d):
    """
    Cleans up a dictionary by removing empty or None values recursively.

    Parameters:
    - d (dict): The dictionary to be cleaned up.

    Returns:
    - dict or None: The cleaned up dictionary. If the resulting dictionary is
    empty, returns None.
    """
    new_dict = {}
    for key, value in d.items():
        entry = None
        if value and str(value) != "":
            if isinstance(value, list):
                entry = cleanup_list(value)
            elif isinstance(value, dict):
                entry = cleanup_dict(value)
            else:
                entry = value
        if entry:
            new_dict[key] = entry
    return new_dict


def import_root_component(vdr_file):
    """
    Imports the root component from the given bom file into the csaf
    """
    with open(vdr_file, "r", encoding="utf-8") as f:
        bom = json.load(f)

    refs = []
    product_tree = {}

    if component := bom["metadata"].get("component"):
        product_tree = {
            "full_product_names": [
                {
                    "name": component.get("name"),
                    "product_id": f"{component.get('name')}:"
                    f"{component.get('version')}",
                    "product_identification_helper": {
                        "purl": component.get("purl"),
                    },
                }
            ]
        }
        if external_references := component.get("externalReferences"):
            refs.extend(
                {
                    "summary": r.get("type"),
                    "url": r.get("url"),
                }
                for r in external_references
            )
    if product_tree:
        LOG.info("Successfully imported root component into the product tree.")
    else:
        LOG.info(
            "Unable to import root component for product tree, "
            "so product tree will not be included."
        )

    return product_tree, refs


def verify_components_present(data, metadata, vdr_file):
    """
    Verify if the required components are present in the given data, metadata,
    and vdr_file.

    Args:
        data (dict): The data dictionary - this is the dictionary
        representing the csaf document itself.
        metadata (dict): The metadata dictionary - this stores the data that
        will be written back out to the csaf.toml.
        vdr_file (str): The path to the vdr_file.

    Returns:
        tuple: A tuple containing the modified template dictionary and the
        modified new_metadata dictionary.
    """
    template = deepcopy(data)
    new_metadata = deepcopy(metadata)
    disclaimer = {
        "category": "legal_disclaimer",
        "text": "Depscan reachable code only covers the project source code, "
        "not the code of dependencies. A dependency may execute "
        "vulnerable code when called even if it is not in the "
        "project's source code. Regard the Depscan-set flag of "
        "'code_not_in_execute_path' with this in mind.",
    }
    if template["document"].get("notes"):
        template["document"]["notes"].append(
            {"category": "legal_disclaimer", "text": disclaimer}
        )
    else:
        template["document"]["notes"] = [disclaimer]

    # Add product tree if not present
    if not template.get("product_tree"):
        [template["product_tree"], extra_ref] = import_root_component(vdr_file)
        if extra_ref and template["document"].get("references"):
            template["document"]["references"] += extra_ref
        elif extra_ref:
            template["document"]["references"] = extra_ref

    # CSAF forbids revision entries unless the status is final, but requires
    # this to be here nonetheless
    if not template["document"]["tracking"].get("revision_history"):
        template["document"]["tracking"]["revision_history"] = []
    else:
        new_metadata["tracking"] = deepcopy(template["document"]["tracking"])

    # Reset the id if it's one we've generated
    if re.match(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}_v",
            new_metadata["tracking"]["id"]
    ):
        new_metadata["tracking"]["id"] = ""

    return template, new_metadata


def add_vulnerabilities(data, results, direct_purls, reached_purls):
    """
    Add vulnerabilities to the given data.

    Parameters:
    - data: The CSAF data so far.
    - results: A list of results containing vulnerability information.
    - direct_purls: A list of direct package URLs.
    - reached_purls: A list of reached package URLs.

    Returns:
    - new_results: The modified data with added vulnerability information.
    """
    new_results = deepcopy(data)
    agg_score = set()
    severity_ref = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
    }
    affected_regex = re.compile(
        r"(?P<lmod>[>=]{1,2})(?P<lower>\w+(?:.\w+)?(?:.\w+)?)-(?P<umod>[<=]{"
        r"1,2})(?P<upper>\w+.(?:\w+.)?(?:\w+)?)",
        re.IGNORECASE,
    )
    reached_dict = calculate_reached(reached_purls, direct_purls)

    for r in results:
        c = CsafOccurence(r)
        new_vuln = c.to_dict()
        agg_score.add(severity_ref.get(c.severity))
        if c.search_string:
            found = reached_dict.get(c.search_string)
            if not found:
                new_vuln["flags"] = [
                    {"label": "vulnerable_code_not_in_execute_path"}
                ]
            elif version_data := re.search(affected_regex, c.vrange):
                if not version_helper(found, version_data.groupdict()):
                    new_vuln["flags"] = [
                        {"label": "vulnerable_code_not_in_execute_path"}
                    ]

        new_results["vulnerabilities"].append(new_vuln)
    if agg_score := list(agg_score):
        agg_score.sort()
        severity_ref = {v: k for k, v in severity_ref.items()}
        agg_severity = (
            severity_ref[agg_score[0]][0]
            + severity_ref[agg_score[0]][1:].lower()
        )
        new_results["document"]["aggregate_severity"] = {"text": agg_severity}

    return new_results


def calculate_reached(reached_purls, direct_purls):
    """
    Calculate the reached packages and their versions.

    This function takes two dictionaries, `reached_purls` and `direct_purls`, as
    input. `reached_purls` contains the reached packages with their URLs, while
    `direct_purls` contains the direct packages with their URLs. The function
    calculates the reached packages and their versions by parsing the URLs.

    Parameters:
        reached_purls (dict): A dictionary containing the reached packages with
            their URLs.
        direct_purls (dict): A dictionary containing the direct packages with
            their URLs.

    Returns:
        dict: A dictionary containing the reached packages as keys and a list
        of versions as values.
    """
    reached_dict = {}
    reached_regex = re.compile(
        r"(?P<pkg>[^/]+/[^/]+)@(?P<version>\w+.(" r"?:\w+.)?(?:\w+)?)",
        re.IGNORECASE,
    )
    for k in reached_purls.keys() | direct_purls.keys():
        if result := re.search(reached_regex, k):
            pkg = result["pkg"]
            version = result["version"]
            reached_dict.setdefault(pkg, []).append(version)
    return reached_dict


def version_helper(reached, vdata):
    """
    Determines if the vulnerability includes the reached version.

    Args:
        reached (list): Package versions that have been reached.
        vdata (dict): A dictionary containing information about the
        version range to be checked.
            - `lower` (str): The lower bound of the version range.
            - `lmod` (str): The lower bound modifier. Possible values are `">"`
                and `">="`.
            - `upper` (str): The upper bound of the version range.
            - `umod` (str): The upper bound modifier. Possible values are `<"`
                and `"<="`.

    Returns:
        bool: True if the version `reached` satisfies the conditions specified
        by `x`, False otherwise.
    """
    mie = vdata["lower"] if vdata["lmod"] != ">=" else None
    mae = vdata["upper"] if vdata["umod"] != "<=" else None
    return any(
        version_compare(_, vdata["lower"], vdata["upper"], mie, mae)
        for _ in reached
    )
