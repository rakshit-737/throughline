# Prior art


- **SIEM / XDR / CNAPP** (Splunk, Elastic, Sentinel, Wiz) correlate alerts at scale, but keep code, build, runtime and intel in separate data models and treat confidence as a severity label. THROUGHLINE is one claim-level graph where every conclusion carries provenance and a confidence you can decompose (`/claims/{id}/explain`).
- **Provenance-graph research** (DARPA TC systems, HOLMES, ATLAS, and the REVENANT/ROOTLINE siblings) reconstructs host activity. THROUGHLINE consumes those reconstructions as independent evidence and fuses them with rule-based detection instead of replacing either.
- **OpenCTI / MISP / STIX** grade intel reliability and confidence, but have no runtime or code layer. THROUGHLINE borrows the Admiralty grading and applies it to every edge.
- **Attribution tools and ACH** (Heuer; DRAGNET, OCCAM) are usually single-engine. Running two with different failure modes as competing claims, with UNKNOWN as a hypothesis, is the measured contribution here.
- **Detection-as-code** (SigmaHQ, pySigma, ANVIL) manages rules. The loop here drafts rules *from an investigation's unseen behaviour* and gates them on real captures before a human sees them.
