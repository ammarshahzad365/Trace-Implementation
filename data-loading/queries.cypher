// Starter queries for the Trace knowledge graph.
//
// Open http://localhost:7474, log in as `neo4j`, and paste one block at a time.
// (Neo4j Browser runs one statement per box -- don't paste the whole file.)
//
// How to read Cypher: MATCH describes a shape you want to find, using ASCII art.
// `(v:Vulnerability)` is a node with the label Vulnerability. `-[:HAS_WEAKNESS]->`
// is an arrow of that type pointing right. RETURN says what to hand back. If you
// return whole paths or nodes you get a picture; return properties and you get a
// table.


// ===========================================================================
// 1. START HERE -- what does the graph even contain?
// ===========================================================================

// A diagram of the whole schema: every label, and which arrows connect them.
// This is the single most useful query for getting your bearings.
CALL db.schema.visualization();

// How many of each kind of thing.
MATCH (n) UNWIND labels(n) AS label
RETURN label, count(*) AS nodes ORDER BY nodes DESC;

// How many of each kind of arrow.
MATCH ()-[r]->()
RETURN type(r) AS relationship, count(*) AS edges ORDER BY edges DESC;


// ===========================================================================
// 2. THE POINT OF THE WHOLE PROJECT
//    A real vulnerability, traced to the defence that stops it.
// ===========================================================================

// Log4Shell -> the weakness class -> how attackers abuse it ->
// the ATT&CK technique -> the D3FEND countermeasure.
// Returning `path` draws it, so you can see the five hops.
MATCH path = (v:Vulnerability {id: "CVE-2021-44228"})
             -[:HAS_WEAKNESS]->(:Weakness)
             <-[:EXPLOITS]-(:AttackPattern)
             -[:MAPS_TO_TECHNIQUE]->(:AttackTechnique)
             <-[:COUNTERS]-(:DefensiveTechnique)
RETURN path;

// The same trace as a readable table, with names instead of ids.
MATCH (v:Vulnerability {id: "CVE-2021-44228"})
      -[:HAS_WEAKNESS]->(w:Weakness)
      <-[:EXPLOITS]-(a:AttackPattern)
      -[:MAPS_TO_TECHNIQUE]->(t:AttackTechnique)
      <-[:COUNTERS]-(d:DefensiveTechnique)
RETURN w.id AS weakness, w.name AS weakness_name,
       a.id AS attack_pattern, a.name AS pattern_name,
       t.id AS technique, t.name AS technique_name,
       d.d3fend_id AS defence, d.name AS defence_name;

// Swap in any CVE you like. This version takes the severity along too.
MATCH (v:Vulnerability {id: "CVE-2017-0144"})   // EternalBlue
      -[:HAS_WEAKNESS]->(w:Weakness)
      <-[:EXPLOITS]-(:AttackPattern)-[:MAPS_TO_TECHNIQUE]->(t:AttackTechnique)
      <-[:COUNTERS]-(d:DefensiveTechnique)
RETURN v.cvss_base_score AS score, v.cvss_base_severity AS severity,
       w.name AS weakness, t.id AS technique, collect(DISTINCT d.name) AS defences;


// ===========================================================================
// 3. SEVERITY -- no traversal needed, thanks to the enrich stage
// ===========================================================================

// The 25 worst-scored CVEs that have a *complete* trace to a defence.
// This is the query the CVSS summary properties exist for: filtering and
// sorting by severity without following an arrow.
MATCH (v:Vulnerability)-[:HAS_WEAKNESS]->(:Weakness)
      <-[:EXPLOITS]-(:AttackPattern)-[:MAPS_TO_TECHNIQUE]->(:AttackTechnique)
      <-[:COUNTERS]-(d:DefensiveTechnique)
WHERE v.cvss_base_score >= 9.0
RETURN v.id AS cve, v.cvss_base_score AS score, v.cvss_version AS cvss,
       count(DISTINCT d) AS defences
ORDER BY score DESC, cve LIMIT 25;

// The full detail behind one CVE's score, including competing CNA assessments.
// (The summary properties are only the headline one -- this is what they came from.)
MATCH (v:Vulnerability {id: "CVE-2021-44228"})-[r]->(s)
WHERE s:CvssV2Score OR s:CvssV3Score OR s:CvssV4Score OR s:SsvcAssessment
RETURN type(r) AS kind, s.assessment_type AS who, s.source AS assessor,
       s.version AS version, s.base_score AS score, s.base_severity AS severity,
       s.vector_string AS vector;


// ===========================================================================
// 4. COVERAGE QUESTIONS -- where the graph has gaps
//    These are the interesting research questions, and they're the queries a
//    table-shaped database is worst at.
// ===========================================================================

// Which weaknesses are exploited by a known attack pattern but have NO route to
// any defence at all? These are the blind spots.
MATCH (w:Weakness)<-[:EXPLOITS]-(:AttackPattern)
WHERE NOT (w)<-[:EXPLOITS]-(:AttackPattern)-[:MAPS_TO_TECHNIQUE]->(:AttackTechnique)
                                            <-[:COUNTERS]-(:DefensiveTechnique)
RETURN w.id AS weakness, w.name AS name, w.abstraction AS abstraction
ORDER BY weakness LIMIT 40;

// Which ATT&CK techniques have the most D3FEND countermeasures, and which have none?
MATCH (t:AttackTechnique)
OPTIONAL MATCH (t)<-[:COUNTERS]-(d:DefensiveTechnique)
RETURN t.id AS technique, t.name AS name, count(DISTINCT d) AS defences
ORDER BY defences DESC, technique LIMIT 30;

// Techniques with zero defensive coverage.
MATCH (t:AttackTechnique)
WHERE NOT (t)<-[:COUNTERS]-(:DefensiveTechnique) AND coalesce(t.deprecated, false) = false
RETURN count(t) AS techniques_with_no_defence;

// How many CVEs reach each stage of the chain? Shows where the data thins out.
MATCH (v:Vulnerability) WITH count(v) AS all_cves
MATCH (v:Vulnerability)-[:HAS_WEAKNESS]->() WITH all_cves, count(DISTINCT v) AS with_weakness
MATCH (v:Vulnerability)-[:HAS_WEAKNESS]->()<-[:EXPLOITS]-()
  WITH all_cves, with_weakness, count(DISTINCT v) AS with_pattern
MATCH (v:Vulnerability)-[:HAS_WEAKNESS]->()<-[:EXPLOITS]-()-[:MAPS_TO_TECHNIQUE]->()
  WITH all_cves, with_weakness, with_pattern, count(DISTINCT v) AS with_technique
MATCH (v:Vulnerability)-[:HAS_WEAKNESS]->()<-[:EXPLOITS]-()-[:MAPS_TO_TECHNIQUE]->()<-[:COUNTERS]-()
RETURN all_cves, with_weakness, with_pattern, with_technique,
       count(DISTINCT v) AS with_defence;


// ===========================================================================
// 5. PROVENANCE -- which catalog said what
// ===========================================================================

// Facts both CWE and NVD independently assert (asserted_by has two entries).
MATCH (v:Vulnerability)-[r:HAS_WEAKNESS]->(w:Weakness)
WHERE size(r.asserted_by) > 1
RETURN v.id AS cve, w.id AS weakness, r.asserted_by AS asserted_by LIMIT 20;

// The CWE hierarchy edges that D3FEND contributed and CWE itself did not --
// the 24 genuinely new ones out of D3FEND's 1,103.
MATCH (a:Weakness)-[r:CHILD_OF]->(b:Weakness)
WHERE r.asserted_by = ["mitre-defend"]
RETURN a.id AS child, a.name AS child_name, b.id AS parent, b.name AS parent_name;

// Which catalog every node came from.
MATCH (n) RETURN n.catalog AS catalog, count(*) AS nodes ORDER BY nodes DESC;


// ===========================================================================
// 6. WALKING THE OTHER DIRECTIONS
// ===========================================================================

// Start from a defence and find what it protects against, all the way to real CVEs.
MATCH (d:DefensiveTechnique {d3fend_id: "D3-NTA"})
      -[:COUNTERS]->(t:AttackTechnique)
OPTIONAL MATCH (t)<-[:MAPS_TO_TECHNIQUE]-(:AttackPattern)-[:EXPLOITS]->(w:Weakness)
                  <-[:HAS_WEAKNESS]-(v:Vulnerability)
RETURN d.name AS defence, t.id AS technique, t.name AS technique_name,
       count(DISTINCT v) AS cves ORDER BY cves DESC;

// Which threat groups use techniques that a given weakness leads to?
MATCH (w:Weakness {id: "CWE-89"})<-[:EXPLOITS]-(:AttackPattern)
      -[:MAPS_TO_TECHNIQUE]->(t:AttackTechnique)<-[:USES]-(g:IntrusionSet)
RETURN g.id AS group, g.name AS name, collect(DISTINCT t.id) AS techniques;

// Why does a defence counter a particular technique? The artifact bridge is the
// reason -- both sides act on the same piece of digital evidence.
MATCH (d:DefensiveTechnique)-[r:COUNTERS]->(t:AttackTechnique {id: "T1078"})
RETURN d.name AS defence, r.def_artifact AS defence_acts_on,
       r.def_artifact_rel AS how, r.off_artifact AS attack_acts_on,
       r.off_artifact_rel AS how_attack LIMIT 15;

// Walk a weakness up its own hierarchy to the most abstract parent.
MATCH path = (w:Weakness {id: "CWE-79"})-[:CHILD_OF*]->(parent:Weakness)
WHERE NOT (parent)-[:CHILD_OF]->(:Weakness)
RETURN path;


// ===========================================================================
// 7. DETECTION SIDE -- ATT&CK's analytics and log sources
// ===========================================================================

// What would you actually need to log to detect a technique?
MATCH (t:AttackTechnique {id: "T1055"})<-[:DETECTS]-(s:DetectionStrategy)
      -[:HAS_ANALYTIC]->(a:Analytic)-[:USES_DATA_COMPONENT]->(c:DataComponent)
      -[hls:HAS_LOG_SOURCE]->(l:LogSource)
RETURN s.name AS strategy, a.name AS analytic, c.name AS data_component,
       l.name AS log_source, hls.channel AS channels LIMIT 25;
