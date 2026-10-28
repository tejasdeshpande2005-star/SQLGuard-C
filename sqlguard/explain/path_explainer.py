"""Human-readable source-to-sink explanations."""
def explain_finding(finding):
    lines=[f"[{finding.severity}] {finding.message}",f"File: {finding.file}:{finding.line}",f"Source: {finding.source}",f"Sink: {finding.sink}","Taint path:"]
    lines.extend(f"  {i+1}. {step}" for i,step in enumerate(finding.path))
    lines += ["Recommended repair:",f"  {finding.repair}"]
    return '\n'.join(lines)
