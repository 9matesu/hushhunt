"""Check -> CWE mapping (report field; triagers/CWE is machine-read by
platforms). Keys are catalog check ids; values official CWE numbers."""

CWE_MAP: dict[str, str] = {
    # v1 passive
    "passive_headers": "CWE-693",          # protection mechanism failure
    "version_disclosure": "CWE-200",       # exposure of sensitive information
    "tls_config": "CWE-326",               # inadequate encryption strength
    "exposed_files": "CWE-538",            # exposure of sensitive info to unauth actor
    "cors_misconfig": "CWE-942",           # permissive cross-domain policy
    "js_endpoints": "CWE-200",
    "js_secret_leak": "CWE-522",           # insufficiently protected credentials
    # v2 active
    "xss_reflected": "CWE-79",
    "xss_dom": "CWE-79",
    "sqli_error": "CWE-89",
    "sqli_boolean": "CWE-89",
    "ssti": "CWE-1336",
    "idor": "CWE-639",                     # authorization bypass beyond user's control
    "jwt_misuse": "CWE-347",               # improper verification of cryptographic signature
    "open_redirect_chain": "CWE-601",
    "graphql_probe": "CWE-200",
    "blind_oast": "CWE-918",               # SSRF
    "mass_assign": "CWE-915",              # mass assignment
    "cmd_inject": "CWE-77",                # command injection
    "nuclei_sweep": "CWE-1104",            # use of unmaintained third-party components (template-driven findings)
}
