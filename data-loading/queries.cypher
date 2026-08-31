// Starter queries for the loaded graph.
//
// Paste one at a time into the Neo4j Browser (http://localhost:7474).
// Every count in the comments was measured against a full load on 2026-08-31:
// 372,739 nodes, 393,418 relationships.
//
// Note the vocabulary is the data's own, not a remodelled one -- the loader
// does not rename links. `RELATED_TO` therefore means four different things
// depending on which labels it joins, and the queries below are explicit about
// which one they want. See README.md, "Known limitations".


// ---------------------------------------------------------------------------
// Shape of the whole graph
// ---------------------------------------------------------------------------

// What labels and relationship types exist, and how they connect.
CALL db.schema.visualization();

// Every (label)-[type]->(label) triple that actually occurs, by volume.
// This is the honest map of the model -- 34 relationship types over 25 labels.
MATCH (a)-[r]->(b)
RETURN labels(a)[0] AS source, type(r) AS rel, labels(b)[0] AS target, count(*) AS n
ORDER BY n DESC;

// Node counts per label.
MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY n DESC;


// ---------------------------------------------------------------------------
// The trace this project exists for: CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND
// ---------------------------------------------------------------------------

// How far the chain actually reaches: 85,643 CVEs (23.8% of 359,355) reach at
// least one defensive technique, touching 124 distinct D3FEND techniques.
// The attrition is in the data, not the load -- 56,702 CVEs have no CWE
// mapping at all, and only 307 CAPEC patterns link to an ATT&CK technique.
MATCH (v:Vulnerability)-[:RELATED_TO]->(:Weakness)-[:RELATED_TO]->(:AttackPattern)
      -[:RELATED_TO]->(:AttackTechnique)<-[:COUNTERS]-(d:DefensiveTechnique)
RETURN count(DISTINCT v) AS cves, count(DISTINCT d) AS defences;

// The same path for one CVE, spelled out -- what defends against Log4Shell?
MATCH path = (v:Vulnerability {id: 'CVE-2021-44228'})-[:RELATED_TO]->(w:Weakness)
      -[:RELATED_TO]->(p:AttackPattern)-[:RELATED_TO]->(t:AttackTechnique)
      <-[:COUNTERS]-(d:DefensiveTechnique)
RETURN path LIMIT 25;

// Which defences answer the most high-severity CVEs.
MATCH (v:Vulnerability)-[:RELATED_TO]->(:Weakness)-[:RELATED_TO]->(:AttackPattern)
      -[:RELATED_TO]->(:AttackTechnique)<-[:COUNTERS]-(d:DefensiveTechnique)
WHERE v.cvss_base_score >= 9.0
RETURN d.d3fend_id AS id, d.name AS defence, count(DISTINCT v) AS critical_cves
ORDER BY critical_cves DESC LIMIT 20;


// ---------------------------------------------------------------------------
// Single steps of the chain, useful on their own
// ---------------------------------------------------------------------------

// The weaknesses behind the most CVEs. (322,036 CVE->Weakness edges in total;
// a further 14,289 point at a CWE *Category* rather than a weakness, which is
// NVD classifying at a coarser level.)
MATCH (v:Vulnerability)-[:RELATED_TO]->(w:Weakness)
RETURN w.id, w.name, count(v) AS cves ORDER BY cves DESC LIMIT 20;

// Attack techniques with no D3FEND countermeasure -- the defensive gaps.
MATCH (t:AttackTechnique) WHERE NOT (t)<-[:COUNTERS]-(:DefensiveTechnique)
RETURN t.id, t.name ORDER BY t.id LIMIT 50;

// Which groups use a given technique, and what malware they use it through.
MATCH (g:IntrusionSet)-[:USES]->(t:AttackTechnique {id: 'T1055'})
RETURN g.id, g.name ORDER BY g.id;

// Mitigations for a weakness, as CWE states them.
MATCH (w:Weakness {id: 'CWE-79'})-[:HAS_MITIGATION]->(m:Mitigation)
RETURN m.phase, m.description;


// ---------------------------------------------------------------------------
// Sanity checks worth re-running after a reload
// ---------------------------------------------------------------------------

// Should be 0. Anything here was created by an endpoint MATCH, not loaded.
MATCH (n) WHERE n.id IS NULL RETURN count(n);

// 56,973 at last load, 56,702 of them CVEs with no CWE mapping. Not a bug, but
// a jump in this number is the cheapest signal that an edge file did not load.
MATCH (n) WHERE NOT (n)--() RETURN labels(n)[0] AS label, count(*) AS n
ORDER BY n DESC;

// Should be 0 -- ids are unique per label by constraint, but this catches an
// id reused across two different labels, which no constraint covers.
MATCH (n) WITH n.id AS id, count(*) AS c WHERE c > 1
RETURN id, c ORDER BY c DESC LIMIT 20;
