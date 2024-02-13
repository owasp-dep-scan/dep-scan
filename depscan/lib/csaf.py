import json
import os
import re
import sys
from copy import deepcopy
from datetime import datetime
from json import JSONDecodeError

import cvss
from cvss import CVSSError
from packageurl import PackageURL

import toml
from vdb.lib import convert_time

from depscan.lib.logger import LOG
from depscan.lib.utils import get_version

TIME_FMT = "%Y-%m-%dT%H:%M:%S"

CWE_MAP = {
    5: 'J2EE Misconfiguration: Data Transmission Without Encryption',
    6: 'J2EE Misconfiguration: Insufficient Session-ID Length',
    7: 'J2EE Misconfiguration: Missing Custom Error Page',
    8: 'J2EE Misconfiguration: Entity Bean Declared Remote',
    9: 'J2EE Misconfiguration: Weak Access Permissions for EJB Methods',
    11: 'ASP.NET Misconfiguration: Creating Debug Binary',
    12: 'ASP.NET Misconfiguration: Missing Custom Error Page',
    13: 'ASP.NET Misconfiguration: Password in Configuration File',
    14: 'Compiler Removal of Code to Clear Buffers',
    15: 'External Control of System or Configuration Setting',
    20: 'Improper Input Validation',
    22: 'Improper Limitation of a Pathname to a Restricted Directory',
    23: 'Relative Path Traversal',
    24: 'Path Traversal',
    25: 'Path Traversal',
    26: 'Path Traversal',
    27: 'Path Traversal',
    28: 'Path Traversal',
    29: 'Path Traversal',
    30: 'Path Traversal',
    31: 'Path Traversal',
    32: 'Path Traversal',
    33: 'Path Traversal',
    34: 'Path Traversal',
    35: 'Path Traversal',
    36: 'Absolute Path Traversal',
    37: 'Path Traversal',
    38: 'Path Traversal',
    39: 'Path Traversal',
    40: 'Path Traversal',
    41: 'Improper Resolution of Path Equivalence',
    42: 'Path Equivalence',
    43: 'Path Equivalence',
    44: 'Path Equivalence',
    45: 'Path Equivalence',
    46: 'Path Equivalence',
    47: 'Path Equivalence',
    48: 'Path Equivalence',
    49: 'Path Equivalence',
    50: 'Path Equivalence',
    51: 'Path Equivalence',
    52: 'Path Equivalence',
    53: 'Path Equivalence',
    54: 'Path Equivalence',
    55: 'Path Equivalence',
    56: 'Path Equivalence',
    57: 'Path Equivalence',
    58: 'Path Equivalence',
    59: 'Improper Link Resolution Before File Access',
    61: 'UNIX Symbolic Link',
    62: 'UNIX Hard Link',
    64: 'Windows Shortcut Following',
    65: 'Windows Hard Link',
    66: 'Improper Handling of File Names that Identify Virtual Resources',
    67: 'Improper Handling of Windows Device Names',
    69: 'Improper Handling of Windows ::DATA Alternate Data Stream',
    71: 'DEPRECATED: Apple .DS_Store',
    72: 'Improper Handling of Apple HFS+ Alternate Data Stream Path',
    73: 'External Control of File Name or Path',
    74: 'Improper Neutralization of Special Elements in Output Used by a '
        'Downstream Component',
    75: 'Failure to Sanitize Special Elements into a Different Plane',
    76: 'Improper Neutralization of Equivalent Special Elements',
    77: 'Improper Neutralization of Special Elements used in a Command',
    78: 'Improper Neutralization of Special Elements used in an OS Command',
    79: 'Improper Neutralization of Input During Web Page Generation',
    80: 'Improper Neutralization of Script-Related HTML Tags in a Web Page',
    81: 'Improper Neutralization of Script in an Error Message Web Page',
    82: 'Improper Neutralization of Script in Attributes of IMG Tags in a Web '
        'Page',
    83: 'Improper Neutralization of Script in Attributes in a Web Page',
    84: 'Improper Neutralization of Encoded URI Schemes in a Web Page',
    85: 'Doubled Character XSS Manipulations',
    86: 'Improper Neutralization of Invalid Characters in Identifiers in Web '
        'Pages',
    87: 'Improper Neutralization of Alternate XSS Syntax',
    88: 'Improper Neutralization of Argument Delimiters in a Command',
    89: 'Improper Neutralization of Special Elements used in an SQL Command',
    90: 'Improper Neutralization of Special Elements used in an LDAP Query',
    91: 'XML Injection',
    92: 'DEPRECATED: Improper Sanitization of Custom Special Characters',
    93: 'Improper Neutralization of CRLF Sequences',
    94: 'Improper Control of Generation of Code',
    95: 'Improper Neutralization of Directives in Dynamically Evaluated Code',
    96: 'Improper Neutralization of Directives in Statically Saved Code',
    97: 'Improper Neutralization of Server-Side Includes',
    98: 'Improper Control of Filename for Include/Require Statement in PHP '
        'Program',
    99: 'Improper Control of Resource Identifiers',
    102: 'Struts: Duplicate Validation Forms',
    103: 'Struts: Incomplete validate',
    104: 'Struts: Form Bean Does Not Extend Validation Class',
    105: 'Struts: Form Field Without Validator',
    106: 'Struts: Plug-in Framework not in Use',
    107: 'Struts: Unused Validation Form',
    108: 'Struts: Unvalidated Action Form',
    109: 'Struts: Validator Turned Off',
    110: 'Struts: Validator Without Form Field',
    111: 'Direct Use of Unsafe JNI',
    112: 'Missing XML Validation',
    113: 'Improper Neutralization of CRLF Sequences in HTTP Headers',
    114: 'Process Control',
    115: 'Misinterpretation of Input',
    116: 'Improper Encoding or Escaping of Output',
    117: 'Improper Output Neutralization for Logs',
    118: 'Incorrect Access of Indexable Resource',
    119: 'Improper Restriction of Operations within the Bounds of a Memory '
         'Buffer',
    120: 'Buffer Copy without Checking Size of Input',
    121: 'Stack-based Buffer Overflow',
    122: 'Heap-based Buffer Overflow',
    123: 'Write-what-where Condition',
    124: 'Buffer Underwrite',
    125: 'Out-of-bounds Read',
    126: 'Buffer Over-read',
    127: 'Buffer Under-read',
    128: 'Wrap-around Error',
    129: 'Improper Validation of Array Index',
    130: 'Improper Handling of Length Parameter Inconsistency',
    131: 'Incorrect Calculation of Buffer Size',
    132: 'DEPRECATED: Miscalculated Null Termination',
    134: 'Use of Externally-Controlled Format String',
    135: 'Incorrect Calculation of Multi-Byte String Length',
    138: 'Improper Neutralization of Special Elements',
    140: 'Improper Neutralization of Delimiters',
    141: 'Improper Neutralization of Parameter/Argument Delimiters',
    142: 'Improper Neutralization of Value Delimiters',
    143: 'Improper Neutralization of Record Delimiters',
    144: 'Improper Neutralization of Line Delimiters',
    145: 'Improper Neutralization of Section Delimiters',
    146: 'Improper Neutralization of Expression/Command Delimiters',
    147: 'Improper Neutralization of Input Terminators',
    148: 'Improper Neutralization of Input Leaders',
    149: 'Improper Neutralization of Quoting Syntax',
    150: 'Improper Neutralization of Escape, Meta, or Control Sequences',
    151: 'Improper Neutralization of Comment Delimiters',
    152: 'Improper Neutralization of Macro Symbols',
    153: 'Improper Neutralization of Substitution Characters',
    154: 'Improper Neutralization of Variable Name Delimiters',
    155: 'Improper Neutralization of Wildcards or Matching Symbols',
    156: 'Improper Neutralization of Whitespace',
    157: 'Failure to Sanitize Paired Delimiters',
    158: 'Improper Neutralization of Null Byte or NUL Character',
    159: 'Improper Handling of Invalid Use of Special Elements',
    160: 'Improper Neutralization of Leading Special Elements',
    161: 'Improper Neutralization of Multiple Leading Special Elements',
    162: 'Improper Neutralization of Trailing Special Elements',
    163: 'Improper Neutralization of Multiple Trailing Special Elements',
    164: 'Improper Neutralization of Internal Special Elements',
    165: 'Improper Neutralization of Multiple Internal Special Elements',
    166: 'Improper Handling of Missing Special Element',
    167: 'Improper Handling of Additional Special Element',
    168: 'Improper Handling of Inconsistent Special Elements',
    170: 'Improper Null Termination',
    172: 'Encoding Error',
    173: 'Improper Handling of Alternate Encoding',
    174: 'Double Decoding of the Same Data',
    175: 'Improper Handling of Mixed Encoding',
    176: 'Improper Handling of Unicode Encoding',
    177: 'Improper Handling of URL Encoding',
    178: 'Improper Handling of Case Sensitivity',
    179: 'Incorrect Behavior Order: Early Validation',
    180: 'Incorrect Behavior Order: Validate Before Canonicalize',
    181: 'Incorrect Behavior Order: Validate Before Filter',
    182: 'Collapse of Data into Unsafe Value',
    183: 'Permissive List of Allowed Inputs',
    184: 'Incomplete List of Disallowed Inputs',
    185: 'Incorrect Regular Expression',
    186: 'Overly Restrictive Regular Expression',
    187: 'Partial String Comparison',
    188: 'Reliance on Data/Memory Layout',
    190: 'Integer Overflow or Wraparound',
    191: 'Integer Underflow',
    192: 'Integer Coercion Error',
    193: 'Off-by-one Error',
    194: 'Unexpected Sign Extension',
    195: 'Signed to Unsigned Conversion Error',
    196: 'Unsigned to Signed Conversion Error',
    197: 'Numeric Truncation Error',
    198: 'Use of Incorrect Byte Ordering',
    200: 'Exposure of Sensitive Information to an Unauthorized Actor',
    201: 'Insertion of Sensitive Information Into Sent Data',
    202: 'Exposure of Sensitive Information Through Data Queries',
    203: 'Observable Discrepancy',
    204: 'Observable Response Discrepancy',
    205: 'Observable Behavioral Discrepancy',
    206: 'Observable Internal Behavioral Discrepancy',
    207: 'Observable Behavioral Discrepancy With Equivalent Products',
    208: 'Observable Timing Discrepancy',
    209: 'Generation of Error Message Containing Sensitive Information',
    210: 'Self-generated Error Message Containing Sensitive Information',
    211: 'Externally-Generated Error Message Containing Sensitive Information',
    212: 'Improper Removal of Sensitive Information Before Storage or Transfer',
    213: 'Exposure of Sensitive Information Due to Incompatible Policies',
    214: 'Invocation of Process Using Visible Sensitive Information',
    215: 'Insertion of Sensitive Information Into Debugging Code',
    216: 'DEPRECATED: Containment Errors',
    217: 'DEPRECATED: Failure to Protect Stored Data from Modification',
    218: 'DEPRECATED: Failure to provide confidentiality for stored data',
    219: 'Storage of File with Sensitive Data Under Web Root',
    220: 'Storage of File With Sensitive Data Under FTP Root',
    221: 'Information Loss or Omission',
    222: 'Truncation of Security-relevant Information',
    223: 'Omission of Security-relevant Information',
    224: 'Obscured Security-relevant Information by Alternate Name',
    225: 'DEPRECATED: General Information Management Problems',
    226: 'Sensitive Information in Resource Not Removed Before Reuse',
    228: 'Improper Handling of Syntactically Invalid Structure',
    229: 'Improper Handling of Values',
    230: 'Improper Handling of Missing Values',
    231: 'Improper Handling of Extra Values',
    232: 'Improper Handling of Undefined Values',
    233: 'Improper Handling of Parameters',
    234: 'Failure to Handle Missing Parameter',
    235: 'Improper Handling of Extra Parameters',
    236: 'Improper Handling of Undefined Parameters',
    237: 'Improper Handling of Structural Elements',
    238: 'Improper Handling of Incomplete Structural Elements',
    239: 'Failure to Handle Incomplete Element',
    240: 'Improper Handling of Inconsistent Structural Elements',
    241: 'Improper Handling of Unexpected Data Type',
    242: 'Use of Inherently Dangerous Function',
    243: 'Creation of chroot Jail Without Changing Working Directory',
    244: 'Improper Clearing of Heap Memory Before Release',
    245: 'J2EE Bad Practices: Direct Management of Connections',
    246: 'J2EE Bad Practices: Direct Use of Sockets',
    247: 'DEPRECATED: Reliance on DNS Lookups in a Security Decision',
    248: 'Uncaught Exception',
    249: 'DEPRECATED: Often Misused: Path Manipulation',
    250: 'Execution with Unnecessary Privileges',
    252: 'Unchecked Return Value',
    253: 'Incorrect Check of Function Return Value',
    256: 'Plaintext Storage of a Password',
    257: 'Storing Passwords in a Recoverable Format',
    258: 'Empty Password in Configuration File',
    259: 'Use of Hard-coded Password',
    260: 'Password in Configuration File',
    261: 'Weak Encoding for Password',
    262: 'Not Using Password Aging',
    263: 'Password Aging with Long Expiration',
    266: 'Incorrect Privilege Assignment',
    267: 'Privilege Defined With Unsafe Actions',
    268: 'Privilege Chaining',
    269: 'Improper Privilege Management',
    270: 'Privilege Context Switching Error',
    271: 'Privilege Dropping / Lowering Errors',
    272: 'Least Privilege Violation',
    273: 'Improper Check for Dropped Privileges',
    274: 'Improper Handling of Insufficient Privileges',
    276: 'Incorrect Default Permissions',
    277: 'Insecure Inherited Permissions',
    278: 'Insecure Preserved Inherited Permissions',
    279: 'Incorrect Execution-Assigned Permissions',
    280: 'Improper Handling of Insufficient Permissions or Privileges ',
    281: 'Improper Preservation of Permissions',
    282: 'Improper Ownership Management',
    283: 'Unverified Ownership',
    284: 'Improper Access Control',
    285: 'Improper Authorization',
    286: 'Incorrect User Management',
    287: 'Improper Authentication',
    288: 'Authentication Bypass Using an Alternate Path or Channel',
    289: 'Authentication Bypass by Alternate Name',
    290: 'Authentication Bypass by Spoofing',
    291: 'Reliance on IP Address for Authentication',
    292: 'DEPRECATED: Trusting Self-reported DNS Name',
    293: 'Using Referer Field for Authentication',
    294: 'Authentication Bypass by Capture-replay',
    295: 'Improper Certificate Validation',
    296: 'Improper Following of a Certificates Chain of Trust',
    297: 'Improper Validation of Certificate with Host Mismatch',
    298: 'Improper Validation of Certificate Expiration',
    299: 'Improper Check for Certificate Revocation',
    300: 'Channel Accessible by Non-Endpoint',
    301: 'Reflection Attack in an Authentication Protocol',
    302: 'Authentication Bypass by Assumed-Immutable Data',
    303: 'Incorrect Implementation of Authentication Algorithm',
    304: 'Missing Critical Step in Authentication',
    305: 'Authentication Bypass by Primary Weakness',
    306: 'Missing Authentication for Critical Function',
    307: 'Improper Restriction of Excessive Authentication Attempts',
    308: 'Use of Single-factor Authentication',
    309: 'Use of Password System for Primary Authentication',
    311: 'Missing Encryption of Sensitive Data',
    312: 'Cleartext Storage of Sensitive Information',
    313: 'Cleartext Storage in a File or on Disk',
    314: 'Cleartext Storage in the Registry',
    315: 'Cleartext Storage of Sensitive Information in a Cookie',
    316: 'Cleartext Storage of Sensitive Information in Memory',
    317: 'Cleartext Storage of Sensitive Information in GUI',
    318: 'Cleartext Storage of Sensitive Information in Executable',
    319: 'Cleartext Transmission of Sensitive Information',
    321: 'Use of Hard-coded Cryptographic Key',
    322: 'Key Exchange without Entity Authentication',
    323: 'Reusing a Nonce, Key Pair in Encryption',
    324: 'Use of a Key Past its Expiration Date',
    325: 'Missing Cryptographic Step',
    326: 'Inadequate Encryption Strength',
    327: 'Use of a Broken or Risky Cryptographic Algorithm',
    328: 'Use of Weak Hash',
    329: 'Generation of Predictable IV with CBC Mode',
    330: 'Use of Insufficiently Random Values',
    331: 'Insufficient Entropy',
    332: 'Insufficient Entropy in PRNG',
    333: 'Improper Handling of Insufficient Entropy in TRNG',
    334: 'Small Space of Random Values',
    335: 'Incorrect Usage of Seeds in Pseudo-Random Number Generator',
    336: 'Same Seed in Pseudo-Random Number Generator',
    337: 'Predictable Seed in Pseudo-Random Number Generator',
    338: 'Use of Cryptographically Weak Pseudo-Random Number Generator',
    339: 'Small Seed Space in PRNG',
    340: 'Generation of Predictable Numbers or Identifiers',
    341: 'Predictable from Observable State',
    342: 'Predictable Exact Value from Previous Values',
    343: 'Predictable Value Range from Previous Values',
    344: 'Use of Invariant Value in Dynamically Changing Context',
    345: 'Insufficient Verification of Data Authenticity',
    346: 'Origin Validation Error',
    347: 'Improper Verification of Cryptographic Signature',
    348: 'Use of Less Trusted Source',
    349: 'Acceptance of Extraneous Untrusted Data With Trusted Data',
    350: 'Reliance on Reverse DNS Resolution for a Security-Critical Action',
    351: 'Insufficient Type Distinction',
    352: 'Cross-Site Request Forgery',
    353: 'Missing Support for Integrity Check',
    354: 'Improper Validation of Integrity Check Value',
    356: 'Product UI does not Warn User of Unsafe Actions',
    357: 'Insufficient UI Warning of Dangerous Operations',
    358: 'Improperly Implemented Security Check for Standard',
    359: 'Exposure of Private Personal Information to an Unauthorized Actor',
    360: 'Trust of System Event Data',
    362: 'Concurrent Execution using Shared Resource with Improper '
         'Synchronization',
    363: 'Race Condition Enabling Link Following',
    364: 'Signal Handler Race Condition',
    365: 'DEPRECATED: Race Condition in Switch',
    366: 'Race Condition within a Thread',
    367: 'Time-of-check Time-of-use',
    368: 'Context Switching Race Condition',
    369: 'Divide By Zero',
    370: 'Missing Check for Certificate Revocation after Initial Check',
    372: 'Incomplete Internal State Distinction',
    373: 'DEPRECATED: State Synchronization Error',
    374: 'Passing Mutable Objects to an Untrusted Method',
    375: 'Returning a Mutable Object to an Untrusted Caller',
    377: 'Insecure Temporary File',
    378: 'Creation of Temporary File With Insecure Permissions',
    379: 'Creation of Temporary File in Directory with Insecure Permissions',
    382: 'J2EE Bad Practices: Use of System.exit',
    383: 'J2EE Bad Practices: Direct Use of Threads',
    384: 'Session Fixation',
    385: 'Covert Timing Channel',
    386: 'Symbolic Name not Mapping to Correct Object',
    390: 'Detection of Error Condition Without Action',
    391: 'Unchecked Error Condition',
    392: 'Missing Report of Error Condition',
    393: 'Return of Wrong Status Code',
    394: 'Unexpected Status Code or Return Value',
    395: 'Use of NullPointerException Catch to Detect NULL Pointer Dereference',
    396: 'Declaration of Catch for Generic Exception',
    397: 'Declaration of Throws for Generic Exception',
    400: 'Uncontrolled Resource Consumption',
    401: 'Missing Release of Memory after Effective Lifetime',
    402: 'Transmission of Private Resources into a New Sphere',
    403: 'Exposure of File Descriptor to Unintended Control Sphere',
    404: 'Improper Resource Shutdown or Release',
    405: 'Asymmetric Resource Consumption',
    406: 'Insufficient Control of Network Message Volume',
    407: 'Inefficient Algorithmic Complexity',
    408: 'Incorrect Behavior Order: Early Amplification',
    409: 'Improper Handling of Highly Compressed Data',
    410: 'Insufficient Resource Pool',
    412: 'Unrestricted Externally Accessible Lock',
    413: 'Improper Resource Locking',
    414: 'Missing Lock Check',
    415: 'Double Free',
    416: 'Use After Free',
    419: 'Unprotected Primary Channel',
    420: 'Unprotected Alternate Channel',
    421: 'Race Condition During Access to Alternate Channel',
    422: 'Unprotected Windows Messaging Channel',
    423: 'DEPRECATED: Proxied Trusted Channel',
    424: 'Improper Protection of Alternate Path',
    425: 'Direct Request',
    426: 'Untrusted Search Path',
    427: 'Uncontrolled Search Path Element',
    428: 'Unquoted Search Path or Element',
    430: 'Deployment of Wrong Handler',
    431: 'Missing Handler',
    432: 'Dangerous Signal Handler not Disabled During Sensitive Operations',
    433: 'Unparsed Raw Web Content Delivery',
    434: 'Unrestricted Upload of File with Dangerous Type',
    435: 'Improper Interaction Between Multiple Correctly-Behaving Entities',
    436: 'Interpretation Conflict',
    437: 'Incomplete Model of Endpoint Features',
    439: 'Behavioral Change in New Version or Environment',
    440: 'Expected Behavior Violation',
    441: 'Unintended Proxy or Intermediary',
    443: 'DEPRECATED: HTTP response splitting',
    444: 'Inconsistent Interpretation of HTTP Requests',
    446: 'UI Discrepancy for Security Feature',
    447: 'Unimplemented or Unsupported Feature in UI',
    448: 'Obsolete Feature in UI',
    449: 'The UI Performs the Wrong Action',
    450: 'Multiple Interpretations of UI Input',
    451: 'User Interface',
    453: 'Insecure Default Variable Initialization',
    454: 'External Initialization of Trusted Variables or Data Stores',
    455: 'Non-exit on Failed Initialization',
    456: 'Missing Initialization of a Variable',
    457: 'Use of Uninitialized Variable',
    458: 'DEPRECATED: Incorrect Initialization',
    459: 'Incomplete Cleanup',
    460: 'Improper Cleanup on Thrown Exception',
    462: 'Duplicate Key in Associative List',
    463: 'Deletion of Data Structure Sentinel',
    464: 'Addition of Data Structure Sentinel',
    466: 'Return of Pointer Value Outside of Expected Range',
    467: 'Use of sizeof',
    468: 'Incorrect Pointer Scaling',
    469: 'Use of Pointer Subtraction to Determine Size',
    470: 'Use of Externally-Controlled Input to Select Classes or Code',
    471: 'Modification of Assumed-Immutable Data',
    472: 'External Control of Assumed-Immutable Web Parameter',
    473: 'PHP External Variable Modification',
    474: 'Use of Function with Inconsistent Implementations',
    475: 'Undefined Behavior for Input to API',
    476: 'NULL Pointer Dereference',
    477: 'Use of Obsolete Function',
    478: 'Missing Default Case in Multiple Condition Expression',
    479: 'Signal Handler Use of a Non-reentrant Function',
    480: 'Use of Incorrect Operator',
    481: 'Assigning instead of Comparing',
    482: 'Comparing instead of Assigning',
    483: 'Incorrect Block Delimitation',
    484: 'Omitted Break Statement in Switch',
    486: 'Comparison of Classes by Name',
    487: 'Reliance on Package-level Scope',
    488: 'Exposure of Data Element to Wrong Session',
    489: 'Active Debug Code',
    491: 'Public cloneable',
    492: 'Use of Inner Class Containing Sensitive Data',
    493: 'Critical Public Variable Without Final Modifier',
    494: 'Download of Code Without Integrity Check',
    495: 'Private Data Structure Returned From A Public Method',
    496: 'Public Data Assigned to Private Array-Typed Field',
    497: 'Exposure of Sensitive System Information to an Unauthorized Control '
         'Sphere',
    498: 'Cloneable Class Containing Sensitive Information',
    499: 'Serializable Class Containing Sensitive Data',
    500: 'Public Static Field Not Marked Final',
    501: 'Trust Boundary Violation',
    502: 'Deserialization of Untrusted Data',
    506: 'Embedded Malicious Code',
    507: 'Trojan Horse',
    508: 'Non-Replicating Malicious Code',
    509: 'Replicating Malicious Code',
    510: 'Trapdoor',
    511: 'Logic/Time Bomb',
    512: 'Spyware',
    514: 'Covert Channel',
    515: 'Covert Storage Channel',
    516: 'DEPRECATED: Covert Timing Channel',
    520: '.NET Misconfiguration: Use of Impersonation',
    521: 'Weak Password Requirements',
    522: 'Insufficiently Protected Credentials',
    523: 'Unprotected Transport of Credentials',
    524: 'Use of Cache Containing Sensitive Information',
    525: 'Use of Web Browser Cache Containing Sensitive Information',
    526: 'Cleartext Storage of Sensitive Information in an Environment '
         'Variable',
    527: 'Exposure of Version-Control Repository to an Unauthorized Control '
         'Sphere',
    528: 'Exposure of Core Dump File to an Unauthorized Control Sphere',
    529: 'Exposure of Access Control List Files to an Unauthorized Control '
         'Sphere',
    530: 'Exposure of Backup File to an Unauthorized Control Sphere',
    531: 'Inclusion of Sensitive Information in Test Code',
    532: 'Insertion of Sensitive Information into Log File',
    533: 'DEPRECATED: Information Exposure Through Server Log Files',
    534: 'DEPRECATED: Information Exposure Through Debug Log Files',
    535: 'Exposure of Information Through Shell Error Message',
    536: 'Servlet Runtime Error Message Containing Sensitive Information',
    537: 'Java Runtime Error Message Containing Sensitive Information',
    538: 'Insertion of Sensitive Information into Externally-Accessible File or'
         ' Directory',
    539: 'Use of Persistent Cookies Containing Sensitive Information',
    540: 'Inclusion of Sensitive Information in Source Code',
    541: 'Inclusion of Sensitive Information in an Include File',
    542: 'DEPRECATED: Information Exposure Through Cleanup Log Files',
    543: 'Use of Singleton Pattern Without Synchronization in a Multithreaded '
         'Context',
    544: 'Missing Standardized Error Handling Mechanism',
    545: 'DEPRECATED: Use of Dynamic Class Loading',
    546: 'Suspicious Comment',
    547: 'Use of Hard-coded, Security-relevant Constants',
    548: 'Exposure of Information Through Directory Listing',
    549: 'Missing Password Field Masking',
    550: 'Server-generated Error Message Containing Sensitive Information',
    551: 'Incorrect Behavior Order: Authorization Before Parsing and '
         'Canonicalization',
    552: 'Files or Directories Accessible to External Parties',
    553: 'Command Shell in Externally Accessible Directory',
    554: 'ASP.NET Misconfiguration: Not Using Input Validation Framework',
    555: 'J2EE Misconfiguration: Plaintext Password in Configuration File',
    556: 'ASP.NET Misconfiguration: Use of Identity Impersonation',
    558: 'Use of getlogin',
    560: 'Use of umask',
    561: 'Dead Code',
    562: 'Return of Stack Variable Address',
    563: 'Assignment to Variable without Use',
    564: 'SQL Injection: Hibernate',
    565: 'Reliance on Cookies without Validation and Integrity Checking',
    566: 'Authorization Bypass Through User-Controlled SQL Primary Key',
    567: 'Unsynchronized Access to Shared Data in a Multithreaded Context',
    568: 'finalize',
    570: 'Expression is Always False',
    571: 'Expression is Always True',
    572: 'Call to Thread run',
    573: 'Improper Following of Specification by Caller',
    574: 'EJB Bad Practices: Use of Synchronization Primitives',
    575: 'EJB Bad Practices: Use of AWT Swing',
    576: 'EJB Bad Practices: Use of Java I/O',
    577: 'EJB Bad Practices: Use of Sockets',
    578: 'EJB Bad Practices: Use of Class Loader',
    579: 'J2EE Bad Practices: Non-serializable Object Stored in Session',
    580: 'clone',
    581: 'Object Model Violation: Just One of Equals and Hashcode Defined',
    582: 'Array Declared Public, Final, and Static',
    583: 'finalize',
    584: 'Return Inside Finally Block',
    585: 'Empty Synchronized Block',
    586: 'Explicit Call to Finalize',
    587: 'Assignment of a Fixed Address to a Pointer',
    588: 'Attempt to Access Child of a Non-structure Pointer',
    589: 'Call to Non-ubiquitous API',
    590: 'Free of Memory not on the Heap',
    591: 'Sensitive Data Storage in Improperly Locked Memory',
    592: 'DEPRECATED: Authentication Bypass Issues',
    593: 'Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects '
         'are Created',
    594: 'J2EE Framework: Saving Unserializable Objects to Disk',
    595: 'Comparison of Object References Instead of Object Contents',
    596: 'DEPRECATED: Incorrect Semantic Object Comparison',
    597: 'Use of Wrong Operator in String Comparison',
    598: 'Use of GET Request Method With Sensitive Query Strings',
    599: 'Missing Validation of OpenSSL Certificate',
    600: 'Uncaught Exception in Servlet ',
    601: 'URL Redirection to Untrusted Site',
    602: 'Client-Side Enforcement of Server-Side Security',
    603: 'Use of Client-Side Authentication',
    605: 'Multiple Binds to the Same Port',
    606: 'Unchecked Input for Loop Condition',
    607: 'Public Static Final Field References Mutable Object',
    608: 'Struts: Non-private Field in ActionForm Class',
    609: 'Double-Checked Locking',
    610: 'Externally Controlled Reference to a Resource in Another Sphere',
    611: 'Improper Restriction of XML External Entity Reference',
    612: 'Improper Authorization of Index Containing Sensitive Information',
    613: 'Insufficient Session Expiration',
    614: 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
    615: 'Inclusion of Sensitive Information in Source Code Comments',
    616: 'Incomplete Identification of Uploaded File Variables',
    617: 'Reachable Assertion',
    618: 'Exposed Unsafe ActiveX Method',
    619: 'Dangling Database Cursor',
    620: 'Unverified Password Change',
    621: 'Variable Extraction Error',
    622: 'Improper Validation of Function Hook Arguments',
    623: 'Unsafe ActiveX Control Marked Safe For Scripting',
    624: 'Executable Regular Expression Error',
    625: 'Permissive Regular Expression',
    626: 'Null Byte Interaction Error',
    627: 'Dynamic Variable Evaluation',
    628: 'Function Call with Incorrectly Specified Arguments',
    636: 'Not Failing Securely',
    637: 'Unnecessary Complexity in Protection Mechanism',
    638: 'Not Using Complete Mediation',
    639: 'Authorization Bypass Through User-Controlled Key',
    640: 'Weak Password Recovery Mechanism for Forgotten Password',
    641: 'Improper Restriction of Names for Files and Other Resources',
    642: 'External Control of Critical State Data',
    643: 'Improper Neutralization of Data within XPath Expressions',
    644: 'Improper Neutralization of HTTP Headers for Scripting Syntax',
    645: 'Overly Restrictive Account Lockout Mechanism',
    646: 'Reliance on File Name or Extension of Externally-Supplied File',
    647: 'Use of Non-Canonical URL Paths for Authorization Decisions',
    648: 'Incorrect Use of Privileged APIs',
    649: 'Reliance on Obfuscation or Encryption of Security-Relevant Inputs '
         'without Integrity Checking',
    650: 'Trusting HTTP Permission Methods on the Server Side',
    651: 'Exposure of WSDL File Containing Sensitive Information',
    652: 'Improper Neutralization of Data within XQuery Expressions',
    653: 'Improper Isolation or Compartmentalization',
    654: 'Reliance on a Single Factor in a Security Decision',
    655: 'Insufficient Psychological Acceptability',
    656: 'Reliance on Security Through Obscurity',
    657: 'Violation of Secure Design Principles',
    662: 'Improper Synchronization',
    663: 'Use of a Non-reentrant Function in a Concurrent Context',
    664: 'Improper Control of a Resource Through its Lifetime',
    665: 'Improper Initialization',
    666: 'Operation on Resource in Wrong Phase of Lifetime',
    667: 'Improper Locking',
    668: 'Exposure of Resource to Wrong Sphere',
    669: 'Incorrect Resource Transfer Between Spheres',
    670: 'Always-Incorrect Control Flow Implementation',
    671: 'Lack of Administrator Control over Security',
    672: 'Operation on a Resource after Expiration or Release',
    673: 'External Influence of Sphere Definition',
    674: 'Uncontrolled Recursion',
    675: 'Multiple Operations on Resource in Single-Operation Context',
    676: 'Use of Potentially Dangerous Function',
    680: 'Integer Overflow to Buffer Overflow',
    681: 'Incorrect Conversion between Numeric Types',
    682: 'Incorrect Calculation',
    683: 'Function Call With Incorrect Order of Arguments',
    684: 'Incorrect Provision of Specified Functionality',
    685: 'Function Call With Incorrect Number of Arguments',
    686: 'Function Call With Incorrect Argument Type',
    687: 'Function Call With Incorrectly Specified Argument Value',
    688: 'Function Call With Incorrect Variable or Reference as Argument',
    689: 'Permission Race Condition During Resource Copy',
    690: 'Unchecked Return Value to NULL Pointer Dereference',
    691: 'Insufficient Control Flow Management',
    692: 'Incomplete Denylist to Cross-Site Scripting',
    693: 'Protection Mechanism Failure',
    694: 'Use of Multiple Resources with Duplicate Identifier',
    695: 'Use of Low-Level Functionality',
    696: 'Incorrect Behavior Order',
    697: 'Incorrect Comparison',
    698: 'Execution After Redirect',
    703: 'Improper Check or Handling of Exceptional Conditions',
    704: 'Incorrect Type Conversion or Cast',
    705: 'Incorrect Control Flow Scoping',
    706: 'Use of Incorrectly-Resolved Name or Reference',
    707: 'Improper Neutralization',
    708: 'Incorrect Ownership Assignment',
    710: 'Improper Adherence to Coding Standards',
    732: 'Incorrect Permission Assignment for Critical Resource',
    733: 'Compiler Optimization Removal or Modification of Security-critical '
         'Code',
    749: 'Exposed Dangerous Method or Function',
    754: 'Improper Check for Unusual or Exceptional Conditions',
    755: 'Improper Handling of Exceptional Conditions',
    756: 'Missing Custom Error Page',
    757: 'Selection of Less-Secure Algorithm During Negotiation',
    758: 'Reliance on Undefined, Unspecified, or Implementation-Defined '
         'Behavior',
    759: 'Use of a One-Way Hash without a Salt',
    760: 'Use of a One-Way Hash with a Predictable Salt',
    761: 'Free of Pointer not at Start of Buffer',
    762: 'Mismatched Memory Management Routines',
    763: 'Release of Invalid Pointer or Reference',
    764: 'Multiple Locks of a Critical Resource',
    765: 'Multiple Unlocks of a Critical Resource',
    766: 'Critical Data Element Declared Public',
    767: 'Access to Critical Private Variable via Public Method',
    768: 'Incorrect Short Circuit Evaluation',
    769: 'DEPRECATED: Uncontrolled File Descriptor Consumption',
    770: 'Allocation of Resources Without Limits or Throttling',
    771: 'Missing Reference to Active Allocated Resource',
    772: 'Missing Release of Resource after Effective Lifetime',
    773: 'Missing Reference to Active File Descriptor or Handle',
    774: 'Allocation of File Descriptors or Handles Without Limits or '
         'Throttling',
    775: 'Missing Release of File Descriptor or Handle after Effective '
         'Lifetime',
    776: 'Improper Restriction of Recursive Entity References in DTDs',
    777: 'Regular Expression without Anchors',
    778: 'Insufficient Logging',
    779: 'Logging of Excessive Data',
    780: 'Use of RSA Algorithm without OAEP',
    781: 'Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control '
         'Code',
    782: 'Exposed IOCTL with Insufficient Access Control',
    783: 'Operator Precedence Logic Error',
    784: 'Reliance on Cookies without Validation and Integrity Checking in a '
         'Security Decision',
    785: 'Use of Path Manipulation Function without Maximum-sized Buffer',
    786: 'Access of Memory Location Before Start of Buffer',
    787: 'Out-of-bounds Write',
    788: 'Access of Memory Location After End of Buffer',
    789: 'Memory Allocation with Excessive Size Value',
    790: 'Improper Filtering of Special Elements',
    791: 'Incomplete Filtering of Special Elements',
    792: 'Incomplete Filtering of One or More Instances of Special Elements',
    793: 'Only Filtering One Instance of a Special Element',
    794: 'Incomplete Filtering of Multiple Instances of Special Elements',
    795: 'Only Filtering Special Elements at a Specified Location',
    796: 'Only Filtering Special Elements Relative to a Marker',
    797: 'Only Filtering Special Elements at an Absolute Position',
    798: 'Use of Hard-coded Credentials',
    799: 'Improper Control of Interaction Frequency',
    804: 'Guessable CAPTCHA',
    805: 'Buffer Access with Incorrect Length Value',
    806: 'Buffer Access Using Size of Source Buffer',
    807: 'Reliance on Untrusted Inputs in a Security Decision',
    820: 'Missing Synchronization',
    821: 'Incorrect Synchronization',
    822: 'Untrusted Pointer Dereference',
    823: 'Use of Out-of-range Pointer Offset',
    824: 'Access of Uninitialized Pointer',
    825: 'Expired Pointer Dereference',
    826: 'Premature Release of Resource During Expected Lifetime',
    827: 'Improper Control of Document Type Definition',
    828: 'Signal Handler with Functionality that is not Asynchronous-Safe',
    829: 'Inclusion of Functionality from Untrusted Control Sphere',
    830: 'Inclusion of Web Functionality from an Untrusted Source',
    831: 'Signal Handler Function Associated with Multiple Signals',
    832: 'Unlock of a Resource that is not Locked',
    833: 'Deadlock',
    834: 'Excessive Iteration',
    835: 'Loop with Unreachable Exit Condition',
    836: 'Use of Password Hash Instead of Password for Authentication',
    837: 'Improper Enforcement of a Single, Unique Action',
    838: 'Inappropriate Encoding for Output Context',
    839: 'Numeric Range Comparison Without Minimum Check',
    841: 'Improper Enforcement of Behavioral Workflow',
    842: 'Placement of User into Incorrect Group',
    843: 'Access of Resource Using Incompatible Type',
    862: 'Missing Authorization',
    863: 'Incorrect Authorization',
    908: 'Use of Uninitialized Resource',
    909: 'Missing Initialization of Resource',
    910: 'Use of Expired File Descriptor',
    911: 'Improper Update of Reference Count',
    912: 'Hidden Functionality',
    913: 'Improper Control of Dynamically-Managed Code Resources',
    914: 'Improper Control of Dynamically-Identified Variables',
    915: 'Improperly Controlled Modification of Dynamically-Determined Object '
         'Attributes',
    916: 'Use of Password Hash With Insufficient Computational Effort',
    917: 'Improper Neutralization of Special Elements used in an Expression '
         'Language Statement',
    918: 'Server-Side Request Forgery',
    920: 'Improper Restriction of Power Consumption',
    921: 'Storage of Sensitive Data in a Mechanism without Access Control',
    922: 'Insecure Storage of Sensitive Information',
    923: 'Improper Restriction of Communication Channel to Intended Endpoints',
    924: 'Improper Enforcement of Message Integrity During Transmission in a '
         'Communication Channel',
    925: 'Improper Verification of Intent by Broadcast Receiver',
    926: 'Improper Export of Android Application Components',
    927: 'Use of Implicit Intent for Sensitive Communication',
    939: 'Improper Authorization in Handler for Custom URL Scheme',
    940: 'Improper Verification of Source of a Communication Channel',
    941: 'Incorrectly Specified Destination in a Communication Channel',
    942: 'Permissive Cross-domain Policy with Untrusted Domains',
    943: 'Improper Neutralization of Special Elements in Data Query Logic',
    1004: 'Sensitive Cookie Without HttpOnly Flag',
    1007: 'Insufficient Visual Distinction of Homoglyphs Presented to User',
    1021: 'Improper Restriction of Rendered UI Layers or Frames',
    1022: 'Use of Web Link to Untrusted Target with window.opener Access',
    1023: 'Incomplete Comparison with Missing Factors',
    1024: 'Comparison of Incompatible Types',
    1025: 'Comparison Using Wrong Factors',
    1037: 'Processor Optimization Removal or Modification of '
          'Security-critical Code',
    1038: 'Insecure Automated Optimizations',
    1039: 'Automated Recognition Mechanism with Inadequate Detection or '
          'Handling of Adversarial Input Perturbations',
    1041: 'Use of Redundant Code',
    1042: 'Static Member Data Element outside of a Singleton Class Element',
    1043: 'Data Element Aggregating an Excessively Large Number of '
          'Non-Primitive Elements',
    1044: 'Architecture with Number of Horizontal Layers Outside of Expected '
          'Range',
    1045: 'Parent Class with a Virtual Destructor and a Child Class without a '
          'Virtual Destructor',
    1046: 'Creation of Immutable Text Using String Concatenation',
    1047: 'Modules with Circular Dependencies',
    1048: 'Invokable Control Element with Large Number of Outward Calls',
    1049: 'Excessive Data Query Operations in a Large Data Table',
    1050: 'Excessive Platform Resource Consumption within a Loop',
    1051: 'Initialization with Hard-Coded Network Resource Configuration Data',
    1052: 'Excessive Use of Hard-Coded Literals in Initialization',
    1053: 'Missing Documentation for Design',
    1054: 'Invocation of a Control Element at an Unnecessarily Deep '
          'Horizontal Layer',
    1055: 'Multiple Inheritance from Concrete Classes',
    1056: 'Invokable Control Element with Variadic Parameters',
    1057: 'Data Access Operations Outside of Expected Data Manager Component',
    1058: 'Invokable Control Element in Multi-Thread Context with non-Final '
          'Static Storable or Member Element',
    1059: 'Insufficient Technical Documentation',
    1060: 'Excessive Number of Inefficient Server-Side Data Accesses',
    1061: 'Insufficient Encapsulation',
    1062: 'Parent Class with References to Child Class',
    1063: 'Creation of Class Instance within a Static Code Block',
    1064: 'Invokable Control Element with Signature Containing an Excessive '
          'Number of Parameters',
    1065: 'Runtime Resource Management Control Element in a Component Built '
          'to Run on Application Servers',
    1066: 'Missing Serialization Control Element',
    1067: 'Excessive Execution of Sequential Searches of Data Resource',
    1068: 'Inconsistency Between Implementation and Documented Design',
    1069: 'Empty Exception Block',
    1070: 'Serializable Data Element Containing non-Serializable Item Elements',
    1071: 'Empty Code Block',
    1072: 'Data Resource Access without Use of Connection Pooling',
    1073: 'Non-SQL Invokable Control Element with Excessive Number of Data '
          'Resource Accesses',
    1074: 'Class with Excessively Deep Inheritance',
    1075: 'Unconditional Control Flow Transfer outside of Switch Block',
    1076: 'Insufficient Adherence to Expected Conventions',
    1077: 'Floating Point Comparison with Incorrect Operator',
    1078: 'Inappropriate Source Code Style or Formatting',
    1079: 'Parent Class without Virtual Destructor Method',
    1080: 'Source Code File with Excessive Number of Lines of Code',
    1082: 'Class Instance Self Destruction Control Element',
    1083: 'Data Access from Outside Expected Data Manager Component',
    1084: 'Invokable Control Element with Excessive File or Data Access '
          'Operations',
    1085: 'Invokable Control Element with Excessive Volume of Commented-out '
          'Code',
    1086: 'Class with Excessive Number of Child Classes',
    1087: 'Class with Virtual Method without a Virtual Destructor',
    1088: 'Synchronous Access of Remote Resource without Timeout',
    1089: 'Large Data Table with Excessive Number of Indices',
    1090: 'Method Containing Access of a Member Element from Another Class',
    1091: 'Use of Object without Invoking Destructor Method',
    1092: 'Use of Same Invokable Control Element in Multiple Architectural '
          'Layers',
    1093: 'Excessively Complex Data Representation',
    1094: 'Excessive Index Range Scan for a Data Resource',
    1095: 'Loop Condition Value Update within the Loop',
    1096: 'Singleton Class Instance Creation without Proper Locking or '
          'Synchronization',
    1097: 'Persistent Storable Data Element without Associated Comparison '
          'Control Element',
    1098: 'Data Element containing Pointer Item without Proper Copy Control '
          'Element',
    1099: 'Inconsistent Naming Conventions for Identifiers',
    1100: 'Insufficient Isolation of System-Dependent Functions',
    1101: 'Reliance on Runtime Component in Generated Code',
    1102: 'Reliance on Machine-Dependent Data Representation',
    1103: 'Use of Platform-Dependent Third Party Components',
    1104: 'Use of Unmaintained Third Party Components',
    1105: 'Insufficient Encapsulation of Machine-Dependent Functionality',
    1106: 'Insufficient Use of Symbolic Constants',
    1107: 'Insufficient Isolation of Symbolic Constant Definitions',
    1108: 'Excessive Reliance on Global Variables',
    1109: 'Use of Same Variable for Multiple Purposes',
    1110: 'Incomplete Design Documentation',
    1111: 'Incomplete I/O Documentation',
    1112: 'Incomplete Documentation of Program Execution',
    1113: 'Inappropriate Comment Style',
    1114: 'Inappropriate Whitespace Style',
    1115: 'Source Code Element without Standard Prologue',
    1116: 'Inaccurate Comments',
    1117: 'Callable with Insufficient Behavioral Summary',
    1118: 'Insufficient Documentation of Error Handling Techniques',
    1119: 'Excessive Use of Unconditional Branching',
    1120: 'Excessive Code Complexity',
    1121: 'Excessive McCabe Cyclomatic Complexity',
    1122: 'Excessive Halstead Complexity',
    1123: 'Excessive Use of Self-Modifying Code',
    1124: 'Excessively Deep Nesting',
    1125: 'Excessive Attack Surface',
    1126: 'Declaration of Variable with Unnecessarily Wide Scope',
    1127: 'Compilation with Insufficient Warnings or Errors',
    1164: 'Irrelevant Code',
    1173: 'Improper Use of Validation Framework',
    1174: 'ASP.NET Misconfiguration: Improper Model Validation',
    1176: 'Inefficient CPU Computation',
    1177: 'Use of Prohibited Code',
    1187: 'DEPRECATED: Use of Uninitialized Resource',
    1188: 'Insecure Default Initialization of Resource',
    1189: 'Improper Isolation of Shared Resources on System-on-a-Chip',
    1190: 'DMA Device Enabled Too Early in Boot Phase',
    1191: 'On-Chip Debug and Test Interface With Improper Access Control',
    1192: 'System-on-Chip',
    1193: 'Power-On of Untrusted Execution Core Before Enabling Fabric Access '
          'Control',
    1204: 'Generation of Weak Initialization Vector',
    1209: 'Failure to Disable Reserved Bits',
    1220: 'Insufficient Granularity of Access Control',
    1221: 'Incorrect Register Defaults or Module Parameters',
    1222: 'Insufficient Granularity of Address Regions Protected by Register '
          'Locks',
    1223: 'Race Condition for Write-Once Attributes',
    1224: 'Improper Restriction of Write-Once Bit Fields',
    1229: 'Creation of Emergent Resource',
    1230: 'Exposure of Sensitive Information Through Metadata',
    1231: 'Improper Prevention of Lock Bit Modification',
    1232: 'Improper Lock Behavior After Power State Transition',
    1233: 'Security-Sensitive Hardware Controls with Missing Lock Bit '
          'Protection',
    1234: 'Hardware Internal or Debug Modes Allow Override of Locks',
    1235: 'Incorrect Use of Autoboxing and Unboxing for Performance Critical '
          'Operations',
    1236: 'Improper Neutralization of Formula Elements in a CSV File',
    1239: 'Improper Zeroization of Hardware Register',
    1240: 'Use of a Cryptographic Primitive with a Risky Implementation',
    1241: 'Use of Predictable Algorithm in Random Number Generator',
    1242: 'Inclusion of Undocumented Features or Chicken Bits',
    1243: 'Sensitive Non-Volatile Information Not Protected During Debug',
    1244: 'Internal Asset Exposed to Unsafe Debug Access Level or State',
    1245: 'Improper Finite State Machines',
    1246: 'Improper Write Handling in Limited-write Non-Volatile Memories',
    1247: 'Improper Protection Against Voltage and Clock Glitches',
    1248: 'Semiconductor Defects in Hardware Logic with Security-Sensitive '
          'Implications',
    1249: 'Application-Level Admin Tool with Inconsistent View of Underlying '
          'Operating System',
    1250: 'Improper Preservation of Consistency Between Independent '
          'Representations of Shared State',
    1251: 'Mirrored Regions with Different Values',
    1252: 'CPU Hardware Not Configured to Support Exclusivity of Write and '
          'Execute Operations',
    1253: 'Incorrect Selection of Fuse Values',
    1254: 'Incorrect Comparison Logic Granularity',
    1255: 'Comparison Logic is Vulnerable to Power Side-Channel Attacks',
    1256: 'Improper Restriction of Software Interfaces to Hardware Features',
    1257: 'Improper Access Control Applied to Mirrored or Aliased Memory '
          'Regions',
    1258: 'Exposure of Sensitive System Information Due to Uncleared Debug '
          'Information',
    1259: 'Improper Restriction of Security Token Assignment',
    1260: 'Improper Handling of Overlap Between Protected Memory Ranges',
    1261: 'Improper Handling of Single Event Upsets',
    1262: 'Improper Access Control for Register Interface',
    1263: 'Improper Physical Access Control',
    1264: 'Hardware Logic with Insecure De-Synchronization between Control and '
          'Data Channels',
    1265: 'Unintended Reentrant Invocation of Non-reentrant Code Via Nested '
          'Calls',
    1266: 'Improper Scrubbing of Sensitive Data from Decommissioned Device',
    1267: 'Policy Uses Obsolete Encoding',
    1268: 'Policy Privileges are not Assigned Consistently Between Control and '
          'Data Agents',
    1269: 'Product Released in Non-Release Configuration',
    1270: 'Generation of Incorrect Security Tokens',
    1271: 'Uninitialized Value on Reset for Registers Holding Security '
          'Settings',
    1272: 'Sensitive Information Uncleared Before Debug/Power State Transition',
    1273: 'Device Unlock Credential Sharing',
    1274: 'Improper Access Control for Volatile Memory Containing Boot Code',
    1275: 'Sensitive Cookie with Improper SameSite Attribute',
    1276: 'Hardware Child Block Incorrectly Connected to Parent System',
    1277: 'Firmware Not Updateable',
    1278: 'Missing Protection Against Hardware Reverse Engineering Using '
          'Integrated Circuit',
    1279: 'Cryptographic Operations are run Before Supporting Units are Ready',
    1280: 'Access Control Check Implemented After Asset is Accessed',
    1281: 'Sequence of Processor Instructions Leads to Unexpected Behavior',
    1282: 'Assumed-Immutable Data is Stored in Writable Memory',
    1283: 'Mutable Attestation or Measurement Reporting Data',
    1284: 'Improper Validation of Specified Quantity in Input',
    1285: 'Improper Validation of Specified Index, Position, or Offset in '
          'Input',
    1286: 'Improper Validation of Syntactic Correctness of Input',
    1287: 'Improper Validation of Specified Type of Input',
    1288: 'Improper Validation of Consistency within Input',
    1289: 'Improper Validation of Unsafe Equivalence in Input',
    1290: 'Incorrect Decoding of Security Identifiers ',
    1291: 'Public Key Re-Use for Signing both Debug and Production Code',
    1292: 'Incorrect Conversion of Security Identifiers',
    1293: 'Missing Source Correlation of Multiple Independent Data',
    1294: 'Insecure Security Identifier Mechanism',
    1295: 'Debug Messages Revealing Unnecessary Information',
    1296: 'Incorrect Chaining or Granularity of Debug Components',
    1297: 'Unprotected Confidential Information on Device is Accessible by '
          'OSAT Vendors',
    1298: 'Hardware Logic Contains Race Conditions',
    1299: 'Missing Protection Mechanism for Alternate Hardware Interface',
    1300: 'Improper Protection of Physical Side Channels',
    1301: 'Insufficient or Incomplete Data Removal within Hardware Component',
    1302: 'Missing Security Identifier',
    1303: 'Non-Transparent Sharing of Microarchitectural Resources',
    1304: 'Improperly Preserved Integrity of Hardware Configuration State '
          'During a Power Save/Restore Operation',
    1310: 'Missing Ability to Patch ROM Code',
    1311: 'Improper Translation of Security Attributes by Fabric Bridge',
    1312: 'Missing Protection for Mirrored Regions in On-Chip Fabric Firewall',
    1313: 'Hardware Allows Activation of Test or Debug Logic at Runtime',
    1314: 'Missing Write Protection for Parametric Data Values',
    1315: 'Improper Setting of Bus Controlling Capability in Fabric End-point',
    1316: 'Fabric-Address Map Allows Programming of Unwarranted Overlaps of '
          'Protected and Unprotected Ranges',
    1317: 'Improper Access Control in Fabric Bridge',
    1318: 'Missing Support for Security Features in On-chip Fabrics or Buses',
    1319: 'Improper Protection against Electromagnetic Fault Injection',
    1320: 'Improper Protection for Outbound Error Messages and Alert Signals',
    1321: 'Improperly Controlled Modification of Object Prototype Attributes',
    1322: 'Use of Blocking Code in Single-threaded, Non-blocking Context',
    1323: 'Improper Management of Sensitive Trace Data',
    1324: 'DEPRECATED: Sensitive Information Accessible by Physical Probing '
          'of JTAG Interface',
    1325: 'Improperly Controlled Sequential Memory Allocation',
    1326: 'Missing Immutable Root of Trust in Hardware',
    1327: 'Binding to an Unrestricted IP Address',
    1328: 'Security Version Number Mutable to Older Versions',
    1329: 'Reliance on Component That is Not Updateable',
    1330: 'Remanent Data Readable after Memory Erase',
    1331: 'Improper Isolation of Shared Resources in Network On Chip',
    1332: 'Improper Handling of Faults that Lead to Instruction Skips',
    1333: 'Inefficient Regular Expression Complexity',
    1334: 'Unauthorized Error Injection Can Degrade Hardware Redundancy',
    1335: 'Incorrect Bitwise Shift of Integer',
    1336: 'Improper Neutralization of Special Elements Used in a Template '
          'Engine',
    1338: 'Improper Protections Against Hardware Overheating',
    1339: 'Insufficient Precision or Accuracy of a Real Number',
    1341: 'Multiple Releases of Same Resource or Handle',
    1342: 'Information Exposure through Microarchitectural State after '
          'Transient Execution',
    1351: 'Improper Handling of Hardware Behavior in Exceptionally Cold '
          'Environments',
    1357: 'Reliance on Insufficiently Trustworthy Component',
    1384: 'Improper Handling of Physical or Environmental Conditions',
    1385: 'Missing Origin Validation in WebSockets',
    1386: 'Insecure Operation on Windows Junction / Mount Point',
    1389: 'Incorrect Parsing of Numbers with Different Radices',
    1390: 'Weak Authentication',
    1391: 'Use of Weak Credentials',
    1392: 'Use of Default Credentials',
    1393: 'Use of Default Password',
    1394: 'Use of Default Cryptographic Key',
    1395: 'Dependency on Vulnerable Third-Party Component'
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

REF_MAP = {
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
SORTED_REF_MAP = dict(
    sorted(REF_MAP.items(), key=lambda x: len(x[0]), reverse=True)
)

COMPILED_REF_PATTERNS = {
    re.compile(pattern, re.IGNORECASE): value
    for pattern, value in SORTED_REF_MAP.items()
}

ISSUES_REGEX = re.compile(
    r"(?P<host>github|bitbucket|chromium)(?:.com|.org)/(?P<owner>["
    r"\w\-.]+)/(?P<repo>[\w\-.]+)/issues/(?:detail\?id=)?(?P<id>\d+)",
    re.IGNORECASE,
)
ADVISORY_REGEX = re.compile(
    r"(?P<org>[^\s/.]+).(?:com|org)/(?:\S+/)*/?(?P<id>[\w\-:]+)",
    re.IGNORECASE,
)
BUGZILLA_REGEX = re.compile(
    r"(?<=bugzilla.)(?P<owner>\S+)\.\w{3}/show_bug.cgi\?id=(?P<id>\S+)",
    re.IGNORECASE,
)
USN_REGEX = re.compile(
    r"(?<=usn.ubuntu.com/)[\d\-]+|(?<=ubuntu.com/security/notices/USN-)"
    r"[\d\-]+",
    re.IGNORECASE,
)


def vdr_to_csaf(res):
    """
    Processes a vulnerability from the VDR format to CSAF format.

    :param res: The metadata for a single vulnerability.
    :type res: dict

    :return: The processed vulnerability in CSAF format.
    :rtype: dict
    """
    cve = res.get("id", "")
    acknowledgements = get_acknowledgements(res.get("source", {}))
    [products, product_status] = get_products(
        res.get("affects", []), res.get("properties", [])
    )
    cwe, notes = parse_cwe(res.get("cwes", []))
    cvss_v3 = parse_cvss(res.get("ratings", [{}]))
    description = (
        res.get("description", "")
        .replace("\n", " ")
        .replace("\t", " ")
        .replace("\n", " ")
        .replace("\t", " ")
    )
    ids, references = format_references(res.get("advisories", []))
    orig_date = res.get("published")
    update_date = res.get("updated")
    discovery_date = orig_date or update_date
    vuln = {}
    if cve.startswith("CVE"):
        vuln["cve"] = cve
    vuln["cwe"] = cwe
    vuln["acknowledgements"] = acknowledgements
    vuln["discovery_date"] = str(discovery_date) if discovery_date else None
    vuln["product_status"] = product_status
    vuln["references"] = references
    vuln["ids"] = ids
    vuln["scores"] = [{"cvss_v3": cvss_v3, "products": products}]
    notes.append(
        {
            "category": "general",
            "text": description,
            "details": "Vulnerability Description",
        }
    )
    vuln["notes"] = notes

    return vuln


def get_products(affects, props):
    """
    Generates a list of unique products and a dictionary of version statuses for
    the vulnerability.

    :param affects: Affected and fixed versions with associated purls
    :type affects: list[dict]
    :param props: List of properties
    :type props: list[dict]

    :return: Packages affected by the vulnerability and their statuses
    :rtype: tuple[list[str], dict[str, str]]
    """
    if not affects and not props:
        return [], {}

    known_affected = []
    fixed = []
    products = set()
    for i in affects:
        for v in i.get("versions", []):
            purl = None
            try:
                purl = PackageURL.from_string(i.get("ref", ""))
                namespace = purl.namespace
                pkg_name = purl.name
                version = purl.version
            except ValueError:
                purl = i.get("ref", "")
                namespace = None
                pkg_name = i.get("ref", "")
                version = None
            if purl and v.get("status") == "affected":
                known_affected.append(
                    f'{namespace}/{pkg_name}@{version}')
            elif purl and v.get("status") == "unaffected":
                fixed.append(f'{namespace}/{pkg_name}@{v.get("version")}')
            elif not purl and v.get("status") == "affected":
                known_affected.append(i.get("ref"))
        product = ''
        try:
            purl = PackageURL.from_string(i.get("ref", ""))
            if purl.namespace:
                product += f'{purl.namespace}/'
            product += f'{purl.name}@{purl.version}'
        except ValueError:
            product = i.get("ref", "")
        products.add(product)

    if version_range := [
        {i["name"]: i["value"]}
        for i in props
        if i["name"] == "affectedVersionRange"
    ]:
        for v in version_range:
            products.add(v["affectedVersionRange"])
            known_affected.append(v["affectedVersionRange"])

    known_affected = [
        i.replace("None/", "").replace("@None", "")
        for i in known_affected
    ]
    fixed = [
        i.replace("None/", "").replace("@None", "") for i in fixed
    ]

    return list(products), {"known_affected": known_affected, "fixed": fixed}


def get_acknowledgements(source):
    """
    Generates the acknowledgements from the source data information
    :param source: A dictionary with the source information
    :type source: dict

    :return: A dictionary containing the acknowledgements
    :rtype: dict
    """
    if not source.get("name"):
        return {}

    return {
        "organization": source["name"],
        "urls": [source.get("url")]
    }


def parse_cwe(cwe):
    """
    Takes a list of CWE numbers and returns a single CSAF CWE entry, with any
    additional CWEs returned in notes (CSAF 2.0 only allows one CWE).

    :param cwe: A list of CWE numbers
    :type cwe: list

    :return: A single CSAF CWE entry (dict) and notes (list)
    :rtype: tuple
    """
    fmt_cwe = None
    new_notes = []

    if not cwe:
        return fmt_cwe, new_notes

    for i, cwe_id in enumerate(cwe):
        cwe_name = CWE_MAP.get(cwe_id, "UNABLE TO LOCATE CWE NAME")
        if not cwe_name:
            LOG.warning(
                "We couldn't locate the name of the CWE with the following "
                "id: %s. Help us out by reporting the id at "
                "https://github.com/owasp-dep-scan/dep-scan/issues.", i, )
        if i == 0:
            fmt_cwe = {"id": str(cwe_id), "name": cwe_name, }
        else:
            new_notes.append(
                {"title": f"Additional CWE: {cwe_id}", "audience": "developers",
                    "category": "other", "text": cwe_name, })

    return fmt_cwe, new_notes


def parse_cvss(ratings):
    """
    Parses the CVSS information from pkg_vulnerabilities

    :param ratings: The ratings data
    :type ratings: list[dict]

    :return: The parsed CVSS information as a single dictionary
    :rtype: dict
    """
    if not ratings or not (vector_string := ratings[0].get("vector")):
        return {}
    if not vector_string or vector_string == "None":
        return {}
    try:
        cvss_v3 = cvss.CVSS3(vector_string)
        cvss_v3.check_mandatory()
    except Exception:
        return {}

    cvss_v3_dict = cvss_v3.as_json()

    cvss_v3 = {k: v for k, v in cvss_v3_dict.items() if v != "NOT_DEFINED"}

    return cleanup_dict(cvss_v3)


def format_references(advisories):
    """
    Formats the advisories as references.

    :param advisories: List of dictionaries of advisories online
    :type advisories: list

    :return: A list of dictionaries with the formatted references.
    :rtype: list
    """
    if not advisories:
        return [], []
    ref = [i["url"] for i in advisories]
    fmt_refs = [{"summary": get_ref_summary(r), "url": r} for r in ref]
    ids = []
    id_types = ["Advisory", "Issue", "Ubuntu Security Notice", "Bugzilla"]
    parse = [i for i in fmt_refs if i.get("summary") in id_types]
    refs = [i for i in fmt_refs if i.get("summary") not in id_types]
    for reference in parse:
        url = reference["url"]
        summary = reference["summary"]
        if summary == "Advisory":
            url = url.replace("glsa/", "glsa-")
            if adv := re.search(ADVISORY_REGEX, url):
                system_name = (
                    (adv["org"].capitalize() + " Advisory")
                    .replace("Redhat", "Red Hat")
                    .replace("Zerodayinitiative", "Zero Day Initiative")
                    .replace("Github", "GitHub")
                    .replace("Netapp", "NetApp")
                )
                ids.append({"system_name": system_name, "text": adv["id"]})
                summary = system_name
        elif issue := re.search(ISSUES_REGEX, url):
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
        elif bugzilla := re.search(BUGZILLA_REGEX, url):
            system_name = f"{bugzilla['owner'].capitalize()} Bugzilla"
            system_name = system_name.replace("Redhat", "Red Hat")
            ids.append(
                {"system_name": f"{system_name} ID", "text": bugzilla["id"]}
            )
            summary = system_name
        elif usn := re.search(USN_REGEX, url):
            ids.append({"system_name": summary, "text": f"USN-{usn[0]}"})
        refs.append({"summary": summary, "url": url})
    new_ids = {(idx["system_name"], idx["text"]) for idx in ids}
    ids = [{"system_name": idx[0], "text": idx[1]} for idx in new_ids]
    ids = sorted(ids, key=lambda x: x["text"])
    return ids, refs


def get_ref_summary(url):
    """
    Returns the summary string associated with a given URL.

    :param url: The URL to match against the patterns in the REF_MAP.
    :type url: str

    :return: The summary string corresponding to the matched pattern in REF_MAP.
    :rtype: str

    :raises: TypeError if url is not a string
    """
    if not isinstance(url, str):
        raise TypeError("url must be a string")

    return next(
        (
            value
            for pattern, value in COMPILED_REF_PATTERNS.items()
            if pattern.search(url)
        ),
        "Other",
    )


def parse_revision_history(tracking):
    """
    Parses the revision history from the tracking data.

    :param tracking: The tracking object containing the revision history
    :type tracking: dict

    :return: The updated tracking object
    :rtype: dict
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

    :param tree: The dictionary representing the tree.
    :type tree: dict

    :return: The product tree loaded from the file, or None if file is empty.
    :rtype: dict or None
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
    Parses the given metadata from csaf.toml and generates an output dictionary.

    :param metadata: The data read from csaf.toml

    :return: The processed metadata ready to use in the CSAF document.
    """
    tracking = parse_revision_history(metadata.get("tracking"))
    refs = list(metadata.get("reference"))
    notes = list(metadata.get("note"))
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

    :param metadata: The toml data
    """

    return metadata


def export_csaf(pkg_vulnerabilities, src_dir, reports_dir, bom_file):
    """
    Generates a CSAF 2.0 JSON document from the results.

    :param pkg_vulnerabilities: List of vulnerabilities
    :type pkg_vulnerabilities: list
    :param src_dir: The source directory.
    :type src_dir: str
    :param reports_dir: The reports directory.
    :type reports_dir: str
    :param bom_file: The BOM file path
    :type bom_file: str

    """
    toml_file_path = os.getenv(
        "DEPSCAN_CSAF_TEMPLATE", os.path.join(src_dir, "csaf.toml")
    )
    metadata = import_csaf_toml(toml_file_path)
    metadata = toml_compatibility(metadata)
    template = parse_toml(metadata)
    new_results = add_vulnerabilities(template, pkg_vulnerabilities)
    new_results = cleanup_dict(new_results)
    [new_results, metadata] = verify_components_present(
        new_results, metadata, bom_file
    )

    outfile = os.path.join(
        reports_dir,
        f"csaf_v{new_results['document']['tracking']['version']}.json",
    )

    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(new_results, f, indent=4, sort_keys=True)
    LOG.info("CSAF report written to %s", outfile)
    write_toml(toml_file_path, metadata)


def import_csaf_toml(toml_file_path):
    """
    Reads the csaf.toml file and returns it as a dictionary.

    :param toml_file_path: The path to the csaf.toml file.
    :type toml_file_path: str

    :return: A dictionary containing the parsed contents of the csaf.toml.
    :rtype: dict

    :raises TOMLDecodeError: If the TOML is invalid.
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
                sys.exit(1)
    except FileNotFoundError:
        write_toml(toml_file_path)
        return import_csaf_toml(toml_file_path)

    return toml_compatibility(toml_data)


def write_toml(toml_file_path, metadata=None):
    """
    Writes the toml data out to file. If no toml data is provided, a toml is
    generated based on the default template.

    :param toml_file_path: The filepath to save the TOML template to.
    :type toml_file_path: str
    :param metadata: A dictionary containing the TOML metadata.
    :type metadata: dict

    """
    if not metadata:
        metadata = TOML_TEMPLATE
    metadata["depscan_version"] = get_version()
    with open(toml_file_path, "w", encoding="utf-8") as f:
        toml.dump(metadata, f)
    LOG.debug("The csaf.toml has been updated at %s", toml_file_path)


def cleanup_list(d):
    """
    Cleans up a list by removing empty or None values recursively.

    :param d: The list to be cleaned up.

    :return: The new list or None
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

    :param d: The dictionary to be cleaned up.

    :return: The new dictionary or None
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


def import_root_component(bom_file):
    """
    Import the root component from the VDR file if no product tree is present
    and gene    external references.

    :param bom_file: The path to the VDR file.
    :type bom_file: str

    :returns: The product tree (dict) and additional references (list of dicts).
    :rtype: tuple
    """
    with open(bom_file, "r", encoding="utf-8") as f:
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
        LOG.debug("Successfully imported root component into the product tree.")
    else:
        LOG.debug(
            "Unable to import root component for product tree, so product "
            "tree will not be included."
        )

    return product_tree, refs


def verify_components_present(data, metadata, bom_file):
    """
    Verify if the required components are present

    :param data: The dictionary representing the csaf document itself.
    :type data: dict
    :param metadata: The dictionary that will be written back to the csaf.toml.
    :type metadata: dict
    :param bom_file: The path to the vdr_file.
    :type bom_file: str

    :return: The modified template and metadata dictionaries.
    :rtype: tuple
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
        [template["product_tree"], extra_ref] = import_root_component(bom_file)
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
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}_v", new_metadata["tracking"]["id"]
    ):
        new_metadata["tracking"]["id"] = ""

    return template, new_metadata


def add_vulnerabilities(template, pkg_vulnerabilities):
    """
    Add vulnerabilities to the given data.

    :param template: The CSAF data so far.
    :type template: dict
    :param pkg_vulnerabilities: The vulnerabilities to add.
    :type pkg_vulnerabilities: list

    :return: The modified data with added vulnerability information.
    :rtype: dict
    """
    new_results = deepcopy(template)
    agg_score = set()
    severity_ref = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
        "UNKNOWN": 5,
        "NONE": 6,
    }
    for r in pkg_vulnerabilities:
        new_vuln = vdr_to_csaf(r)
        if sev := new_vuln["scores"][0]["cvss_v3"].get("baseSeverity"):
            agg_score.add(severity_ref.get(sev))
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
