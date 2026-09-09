"""External-tool adapter pseudo-check. Nuclei executes via nuclei_runner.py
(REAL binary); this registration exists so signals share the catalog's
wstg/severity plumbing and the verify gate. It is in POC_REQUIRED, so a
nuclei hit can only become a positive through a re-runnable PoC — never on
the tool's own word."""
from .. import register


@register("nuclei_sweep", "WSTG-INFO-09", "high")
def nuclei_placeholder(ctx):
    # never invoked by the pipeline directly; the runner stores signals
    return []
