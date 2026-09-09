"""v2 active modules. Registration happens when the pipeline imports them;
grant scope per module is the CONTRACT (Task 14/17 enforce it): probe =
lower blast radius, deep = needs the stronger grant."""

ACTIVE_MODULES: dict[str, str] = {
    "xss_reflected": "probe",
    "xss_dom": "probe",
    "sqli_error": "probe",
    "sqli_boolean": "deep",
    "ssti": "probe",
    "idor": "deep",
    "jwt_misuse": "probe",
    "open_redirect_chain": "probe",
    "graphql_probe": "probe",
    "blind_oast": "deep",
    "mass_assign": "deep",
    "cmd_inject": "deep",
}
