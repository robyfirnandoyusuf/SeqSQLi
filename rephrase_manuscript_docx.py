#!/usr/bin/env python3
"""Create a readability-edited copy of the SeqSQLi manuscript.

The script edits only body paragraphs that do not contain Word equation objects.
Package relationships, styles, tables, figures, equations, and other DOCX parts
are copied unchanged.
"""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
from xml.etree import ElementTree as ET
import os


SOURCE = Path("docs/manuscript-publication.docx")
OUTPUT = Path("docs/manuscript-publications-rephrase.docx")
TEMP_OUTPUT = Path("docs/manuscript-publications-rephrase.tmp.docx")

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
M = "{http://schemas.openxmlformats.org/officeDocument/2006/math}"
XML_NS = "http://www.w3.org/XML/1998/namespace"


# Keys are ordinal numbers of non-empty top-level body paragraphs.
REPLACEMENTS = {
    8: (
        "Abstract: SQL injection remains a major threat to web applications, and web "
        "application firewalls (WAFs) are widely used to block malicious requests. "
        "Nevertheless, an attacker may evade detection by changing a payload's surface "
        "syntax while preserving its attack semantics. This paper presents SeqSQLi, a "
        "framework that formulates WAF evasion as a finite-horizon Markov decision "
        "process. The agent sequentially applies one of 51 semantics-preserving mutation "
        "operators. An episode is considered successful only when the request passes the "
        "WAF and the injected query returns the target data. We compare PPO, TRPO, and A2C "
        "under identical conditions against ModSecurity CRS v3.3.2 and the learning-based "
        "SafeLine WAF. Against ModSecurity, TRPO achieved an induced false-negative rate "
        "(IFNR) of 99.1% and required an average of 6.07 requests per successful bypass, "
        "compared with IFNRs of 88.9% for PPO and 76.9% for A2C. On the more difficult "
        "error-based corpus, A2C's standard deviation was approximately six to eight times "
        "larger than those of TRPO and PPO. Pairwise reversal experiments identified 35 "
        "ordering dependencies supported by at least two algorithms. Policies trained "
        "against ModSecurity achieved a 0% IFNR when transferred to SafeLine. Direct "
        "training against SafeLine produced WAF evasion in approximately 89% of episodes "
        "but no successful data extraction. These results demonstrate that passing a WAF "
        "does not necessarily preserve the functionality of an SQL injection payload."
    ),
    11: (
        "SQL injection remains a major security threat to web applications and continues "
        "to appear in widely used vulnerability rankings, including the OWASP Top 10 [1] "
        "and the CWE Top 25 [2]. SQL injection occurs when untrusted input is incorporated "
        "into a database query without adequate validation or parameterization. The "
        "database may then interpret part of the input as executable SQL rather than as "
        "data [3]. Successful exploitation can expose sensitive information, bypass "
        "authentication controls, modify stored data, or compromise the underlying host. "
        "A web application firewall (WAF) provides an additional defense layer by "
        "inspecting incoming HTTP requests and blocking those classified as malicious."
    ),
    12: (
        "WAFs commonly use rule-based or learning-based detection. ModSecurity with the "
        "OWASP Core Rule Set is a representative rule-based system. It evaluates requests "
        "using signatures and regular-expression rules [4], making its decisions "
        "relatively transparent and inexpensive to deploy. However, a rule can detect only "
        "the patterns that it represents. The same SQL injection can be written in many "
        "semantically equivalent forms by inserting comments, encoding characters, or "
        "replacing keywords and functions with equivalent constructs. These changes can "
        "prevent a malicious payload from matching a static rule while preserving its "
        "behavior [5,6]. Learning-based WAFs use a different detection mechanism. For "
        "example, Chaitin SafeLine employs a classifier trained on traffic data rather than "
        "relying exclusively on hand-written rules [7]. Such a classifier can detect "
        "attacks that resemble patterns observed during training. However, substantial "
        "changes to a payload's structure or token sequence may move it outside the learned "
        "distribution and cause it to be classified as benign [8,9]. Consequently, both "
        "detection paradigms may be vulnerable to transformations that alter payload syntax "
        "without changing the intended SQL operation."
    ),
    13: (
        "WAF robustness can be evaluated by submitting live payloads and observing whether "
        "each request is blocked or allowed [4,5]. Prior studies have automated this process "
        "using several search strategies. WAF-A-MoLE explores a mutation tree and selects "
        "payloads that reduce a classifier's confidence score [5]. AdvSQLi combines a "
        "context-free grammar with Monte Carlo Tree Search to generate structurally valid "
        "payloads [6]. Reinforcement-learning approaches formulate the search as a "
        "sequential decision problem in which WAF feedback provides the reward signal. "
        "SSQLi learns a Soft Actor-Critic policy over an attack-strategy matrix [8], whereas "
        "XploitSQL combines a fine-tuned language model with an actor-critic search loop "
        "[10]. BWAFSQLi instead uses grammar-based generation with adaptive operator "
        "selection and reports results across eleven firewalls [11]."
    ),
    14: (
        "Despite this progress, three questions remain insufficiently studied. First, prior "
        "RL-based studies typically evaluate a single search algorithm, so the relative "
        "performance of on-policy algorithms under identical conditions is unknown. Second, "
        "most studies evaluate one firewall or one detection paradigm. It therefore remains "
        "unclear whether a policy trained against a rule-based WAF can transfer to a "
        "learning-based WAF. Third, existing methods generally select mutations from an "
        "unordered action set and do not explicitly model dependencies between successive "
        "transformations. Such dependencies can be important because one transformation may "
        "be valid or effective only after another transformation has modified the payload."
    ),
    17: (
        "Accordingly, this study addresses three questions: how the selected on-policy "
        "algorithms perform under identical conditions, whether mutation order affects "
        "bypass success, and whether policies learned against a rule-based WAF transfer to "
        "a learning-based WAF. The transfer experiment is interpreted specifically with "
        "respect to the two evaluated deployments."
    ),
    18: "This paper makes the following contributions:",
    19: (
        "1. We formulate WAF evasion as a sequential mutation Markov decision process and "
        "compare PPO, TRPO, and A2C in a shared experimental environment. Success requires "
        "both WAF evasion and confirmed data extraction."
    ),
    20: (
        "2. Using a three-seed protocol on the error-based corpus, we show that average "
        "success and training stability are distinct properties. A2C exhibited a standard "
        "deviation approximately six to eight times larger than those of TRPO and PPO."
    ),
    21: (
        "3. We use pairwise reversal experiments to identify 35 directional mutation "
        "dependencies supported by at least two of the three algorithms."
    ),
    22: (
        "4. To our knowledge, we provide the first controlled evaluation of zero-shot "
        "evasion-policy transfer from a rule-based WAF to a learning-based WAF among the "
        "studies reviewed in Section 2."
    ),
    23: "2. Related Work",
    26: (
        "An effective WAF-evasion payload must satisfy a stricter constraint than an input "
        "that merely passes the firewall. SQL injection includes several extraction "
        "channels. Union-based injection appends a UNION SELECT clause to return database "
        "values in the application response. Error-based injection deliberately triggers "
        "database errors that disclose target values. Blind injection infers values through "
        "conditional responses without an explicit output channel. In every case, the "
        "mutated payload must remain syntactically valid and preserve the intended database "
        "operation after it passes the WAF. This requirement differs from many image-based "
        "adversarial examples, where a perturbation need not satisfy a formal grammar "
        "[9,16]. A malformed SQL payload may pass the WAF but still fail to execute. "
        "Therefore, WAF bypass alone is insufficient as a success criterion; successful "
        "data extraction must also be verified. Section 4.4 shows that this distinction is "
        "essential when evaluating the learning-based WAF."
    ),
    29: (
        "Payload-based WAF testing submits constructed requests, observes the resulting "
        "verdicts, and uses this feedback to refine subsequent inputs [11]. Existing methods "
        "can be grouped into mutation-based, grammar-guided, and reinforcement-learning "
        "approaches."
    ),
    30: (
        "Mutation-based fuzzing provides a relatively inexpensive search strategy. "
        "WAF-A-MoLE traverses a mutation tree and selects the child payload that most reduces "
        "the target classifier's confidence [5]. Appelt et al. proposed an evolutionary "
        "method that learns which transformation families have previously succeeded and "
        "prioritizes them in later tests [18]. A limitation of unconstrained mutation is that "
        "many transformations can produce invalid SQL. Grammar-guided methods address this "
        "problem during generation. AdvSQLi uses a context-free grammar and Monte Carlo Tree "
        "Search to explore executable payload candidates [6]. BWAFSQLi combines 18 attack "
        "scenarios with 15 mutation strategies and adaptively selects operators and "
        "positions. The authors reported false-negative-rate increases of up to 93.39% "
        "against gray-box firewalls and 58.49% against black-box firewalls [11]. "
        "Reinforcement learning instead models payload generation as a sequential decision "
        "problem, using the WAF response as a reward signal. Hemmati and Hadavi evaluated a "
        "Deep Q-Network against ModSecurity, Naxsi, and WAF-Brain [19]. SSQLi applies Soft "
        "Actor-Critic to 14 attack strategies and reports bypass rates of up to 97.39% "
        "across six targets [8]. XploitSQL uses a T5 language model to propose payloads and "
        "an actor-critic loop to refine the search [10]. Despite their differences, these "
        "methods generally choose transformations from an unordered action set and do not "
        "explicitly represent dependencies between successive mutations."
    ),
    33: (
        "Reinforcement learning has also been used to evade learned security classifiers in "
        "related domains, including static malware detection [20]. Existing RL-based WAF "
        "evasion studies generally fix the optimization algorithm: Hemmati and Hadavi [19] "
        "use a Deep Q-Network, SSQLi [8] uses Soft Actor-Critic, and XploitSQL [10] combines "
        "a language-model prior with an actor-critic loop. This literature leaves three "
        "limitations. The optimizer has not been isolated as an experimental variable under "
        "a common environment; mutation operators are generally treated as an unordered "
        "set; and zero-shot policy transfer from a rule-based WAF to a learning-based WAF "
        "has not been characterized. SeqSQLi addresses these limitations by holding the "
        "environment and corpus constant while varying the optimizer, including the previous "
        "action in the state representation, and evaluating transfer between the two WAF "
        "deployments."
    ),
    35: (
        "We designed a common experimental environment to address the three research "
        "questions. Across experiments, only the optimizer, payload corpus, or target WAF "
        "was changed. Holding the remaining factors constant reduces confounding and allows "
        "observed differences to be associated with the factor under evaluation. As shown "
        "in Figure 2, the policy observes the current payload, applies one mutation, submits "
        "the resulting request, and receives a reward derived from the firewall and "
        "application responses."
    ),
    47: (
        "We evaluate two corpora containing 108 payloads each, both targeting Less-1 of the "
        "sqli-labs testbed [23]. The union corpus contains union-based payloads, whereas the "
        "error corpus contains error-based payloads. This separation allows injection type "
        "to be evaluated independently of algorithm choice. Each corpus contains 36 "
        "payloads in each of three difficulty tiers: trivial, medium, and complex. Before "
        "introducing a WAF, we verified that every payload executed successfully against the "
        "unprotected application. Consequently, the baseline false-negative rate reflects "
        "WAF behavior rather than invalid source payloads."
    ),
    49: (
        "The rule-based target is ModSecurity with OWASP Core Rule Set v3.3.2, deployed "
        "behind nginx and exposed on port 8080 [4]. ModSecurity evaluates incoming requests "
        "using a predefined set of rules and blocks requests whose anomaly scores exceed the "
        "configured threshold. The corpus difficulty tiers represent an increasing number "
        "of detection patterns that must be avoided: trivial payloads require relatively "
        "few transformations, whereas complex payloads require longer ordered mutation "
        "sequences."
    ),
    50: (
        "The learning-based target is Chaitin SafeLine Community Edition, exposed on port "
        "8888 [7]. In this study, SafeLine is treated as a black-box learning-based WAF; the "
        "agent observes only the HTTP status code and response body. Both WAFs protect the "
        "same sqli-labs Less-1 application and use the same application response marker to "
        "confirm successful data extraction. This shared backend allows the strict success "
        "criterion to be applied consistently to both targets. Because SafeLine's internal "
        "model is not directly observed, interpretations of its behavior are limited to the "
        "responses measured in these experiments."
    ),
    58: (
        "We used the union corpus to compare the three optimization algorithms under the "
        "same environment, reward function, and training budget of 1.5 × 10⁵ steps. Table 1 "
        "summarizes the results against ModSecurity. TRPO achieved the highest IFNR (99.1%) "
        "and the lowest SPBARC (6.07) among the learned agents. PPO and A2C achieved IFNRs of "
        "88.9% and 76.9%, respectively. The unguided random mutator achieved an IFNR of only "
        "3.7% and required an average of 216 requests per successful bypass. These results "
        "give TRPO the best observed effectiveness and request efficiency under the "
        "evaluated training budget. From a defensive perspective, request count may also be "
        "relevant because longer search sequences provide more opportunities for detection."
    ),
    60: (
        "The per-tier results show that most of the difference occurred on complex payloads. "
        "All three agents achieved success rates at or near 100% on the trivial and medium "
        "tiers. On the complex tier, TRPO achieved 97.2%, compared with 66.7% for PPO and "
        "33.3% for A2C (Figure 3). The maximum episode horizon remained fixed at T = 15, so "
        "the difference did not result from different configured horizons. Instead, complex "
        "payloads required longer successful mutation sequences and therefore created a "
        "longer effective decision horizon under sparse reward. Under the evaluated "
        "1.5 × 10⁵-step budget, the results are consistent with an interaction between "
        "mutation-chain length and optimizer stability. However, the union-corpus experiment "
        "used only one training seed per algorithm. The complex-tier ranking should therefore "
        "be treated as preliminary; multi-seed replication is required to estimate its "
        "stability and magnitude."
    ),
    62: (
        "Aggregate metrics describe overall performance but do not show how the policies "
        "construct successful payloads. The trajectories learned by TRPO indicate that "
        "longer mutation chains were required as payload difficulty increased. For a trivial "
        "payload using database(), the successful trajectory applied four operators: case → "
        "newline → func_sp_nbsp → null_byte. These operators changed keyword capitalization, "
        "replaced separators with encoded newline characters, modified function spacing, and "
        "terminated the trailing comment with a null byte. For a medium payload retrieving "
        "table names with GROUP_CONCAT, the successful trajectory added agg_swap, which "
        "replaced GROUP_CONCAT with JSON_ARRAYAGG. The complex payload targeting the `users` "
        "table added ident_backtick followed by hex_to_char, producing a seven-step chain. "
        "In this trajectory, backtick escaping of the identifier preceded conversion of the "
        "hexadecimal constant 0x3a to CHAR(58), consistent with the directional dependency "
        "reported in Section 4.3. Thus, chain length increased with the number of detection "
        "patterns that had to be avoided rather than simply with the number of characters in "
        "the original SQL query."
    ),
    63: "4.2. Performance and Stability on Error-Based Payloads",
    64: (
        "Error-based payloads produced substantially lower data-extraction success than "
        "union-based payloads. To estimate run-to-run variability, each algorithm was trained "
        "with three random seeds. Table 2 reports the mean and standard deviation across "
        "these runs. The highest IFNR decreased from 99.1% on the union corpus to 30.3% on "
        "the error corpus. TRPO and PPO had standard deviations of 2.3 and 1.9 percentage "
        "points, respectively, whereas A2C had a standard deviation of 14.4 percentage "
        "points. A2C's standard deviation was therefore approximately 6.3 times that of TRPO "
        "and 7.6 times that of PPO. Its seed-level results ranged from 5.6% to 30.6% "
        "(Figure 4). These results indicate that A2C achieved a competitive mean on the "
        "error corpus but was substantially less stable across the evaluated seeds. A "
        "single-seed result could therefore provide a misleading estimate of its performance."
    ),
    67: (
        "The observed variability is consistent with the update mechanisms of the three "
        "algorithms. A2C does not explicitly constrain the magnitude of each policy update, "
        "whereas TRPO and PPO restrict policy changes through trust-region and clipping "
        "mechanisms, respectively. Under sparse rewards, an unfavorable early batch may "
        "therefore have a larger effect on an A2C run. The present experiment does not "
        "directly isolate that mechanism, but it demonstrates that A2C results in this "
        "setting are sensitive to the random seed and should not be reported from a single "
        "run."
    ),
    68: "4.3. Effects of Mutation Ordering",
    69: (
        "Including the previous action in the state allows the policy to condition its next "
        "choice on mutation order. We evaluated this effect by comparing the success rates "
        "of operator pairs in their forward and reversed orders. Among the 1,275 possible "
        "pairs, TRPO, PPO, and A2C exhibited 68, 146, and 137 ordering-dependent pairs, "
        "respectively. Requiring support from at least two algorithms produced 35 consensus "
        "pairs and reduced the influence of optimizer-specific behavior. A unanimity "
        "criterion would retain only newline → func_sp_nbsp and would provide too little "
        "information to characterize broader ordering patterns. We therefore use the "
        "two-of-three criterion while separately identifying the one unanimously supported "
        "pair."
    ),
    70: (
        "Several pairs exhibited strong directional effects (Figure 5). The sequence "
        "ident_backtick → hex_to_char succeeded in 98.0% of evaluated episodes, whereas the "
        "reversed sequence achieved 0.0%. Other pairs showed smaller but consistent "
        "differences: hex_to_char → case achieved 93.2%, compared with 27.4% in reverse, and "
        "null_byte → agg_swap achieved 91.4%, compared with 40.1% in reverse. The pair "
        "newline → func_sp_nbsp showed a positive directional effect for all three "
        "algorithms. These pairwise reversal results provide evidence that specific "
        "operators have directional dependencies within the evaluated environment. An "
        "unordered action representation would not explicitly preserve this information."
    ),
    73: (
        "For the zero-shot transfer experiment, each policy trained against ModSecurity was "
        "evaluated against SafeLine without additional training. All three algorithms "
        "achieved an IFNR of 0% on both corpora: SafeLine blocked more than 900 requests "
        "generated by the transferred policies. To determine whether this result reflected "
        "policy mismatch rather than an inherently unbypassable target, we evaluated a "
        "manually constructed positive-control payload. A standard injection returned HTTP "
        "403, whereas the payload .1--+-'/0 UNION ALL SELECT 1,CURRENT_DATE,3 returned HTTP "
        "200 and displayed the injected row. This payload was not generated by the agent and "
        "appears to lie outside its mutation space because the current operators modify "
        "surface form but do not introduce new column expressions such as CURRENT_DATE. The "
        "positive control therefore confirms that a bypass existed while showing that the "
        "transferred policies did not discover it."
    ),
    75: (
        "Direct training against SafeLine produced a different failure mode. At the episode "
        "level, at least one request passed the WAF in approximately 89% of episodes, but no "
        "episode successfully extracted the target data. At the request level, 846 of 972 "
        "requests (87.0%) returned HTTP 200 but produced SQL errors. Thus, many mutations "
        "changed the payload sufficiently to pass the evaluated classifier but also made the "
        "SQL invalid. In the ModSecurity experiments, some mutation sequences achieved WAF "
        "evasion while preserving data extraction. In the SafeLine experiment, the available "
        "operators did not achieve both objectives simultaneously. This result motivates "
        "semantics-aware operators that preserve executable SQL while exploring "
        "representations relevant to learning-based WAFs."
    ),
    77: (
        "On the union corpus, the observed performance ranking was TRPO > PPO > A2C. This "
        "result is consistent with the hypothesis in Section 2.3 that constrained policy "
        "updates can improve learning in sparse-reward tasks with long effective horizons. "
        "Previous studies report bypass rates of 97.39% for SSQLi [8] and 93.39% for "
        "BWAFSQLi [11], but they do not isolate the optimizer under an identical environment. "
        "In our experiments, all three algorithms performed similarly on trivial and medium "
        "payloads, whereas their performance diverged on complex payloads requiring six- to "
        "seven-step mutation chains. This pattern suggests that the observed ranking is more "
        "closely associated with mutation-chain length and update stability than with SQL "
        "surface length alone. Because this experiment used one seed per algorithm, the "
        "ranking requires multi-seed confirmation."
    ),
    78: (
        "The error corpus revealed a second difference among the algorithms: stability "
        "across random seeds. The highest IFNR decreased from 99.1% on the union corpus to "
        "30.3% on the error corpus, indicating that error-based extraction was more difficult "
        "under the evaluated setup. A2C achieved a mean IFNR of 22.3% but a standard "
        "deviation of 14.4 percentage points, compared with 2.3 for TRPO and 1.9 for PPO. "
        "This large variation is consistent with A2C's unconstrained update mechanism, "
        "although the experiment does not directly establish that mechanism as the cause. "
        "The result demonstrates that single-seed evaluation is inadequate for comparing "
        "A2C in this setting."
    ),
    79: (
        "The 35 mutation-order pairs supported by at least two algorithms indicate that "
        "directional dependencies are not limited to one optimizer. The strongest example, "
        "ident_backtick → hex_to_char, achieved 98.0% success in the forward order and 0.0% "
        "in reverse. Pairwise reversal therefore provides evidence that the order of these "
        "two transformations affects bypass success within the evaluated environment. More "
        "generally, methods that treat mutations as an unordered set may fail to represent "
        "such dependencies. The present results do not establish that the same pairs will "
        "apply to other WAF versions, database backends, or payload corpora."
    ),
    80: (
        "The zero-shot transfer experiment produced the clearest difference between the two "
        "evaluated WAF deployments. Policies trained against ModSecurity achieved an IFNR of "
        "0% when applied to SafeLine. Direct SafeLine training produced WAF evasion in "
        "approximately 89% of episodes but no successful data extraction. Most allowed "
        "requests contained invalid SQL, indicating that the available mutations frequently "
        "traded query validity for WAF evasion. This observation explains the measured "
        "transfer failure more directly than a general distinction between all rule-based "
        "and learning-based WAFs. The result is limited to ModSecurity CRS v3.3.2, the "
        "evaluated SafeLine version, and the current operator set."
    ),
    81: (
        "This study has three main limitations. First, the experiments cover only union-based "
        "and error-based injection. Other injection types and database backends may produce "
        "different mutation dependencies. Second, the transfer experiment evaluates one "
        "rule-based product and one learning-based product. Changes to WAF versions, rules, "
        "or model parameters may alter both evasion and transfer performance. Third, each "
        "payload corpus contains 108 samples evenly divided among three difficulty tiers. "
        "This balanced distribution may not represent production traffic, and the effect of "
        "corpus size on the number and stability of consensus pairs remains unknown. A "
        "further methodological limitation is that the union-corpus comparison used only one "
        "training seed per algorithm."
    ),
    83: (
        "This study introduced SeqSQLi, which formulates WAF evasion as a finite-horizon "
        "sequential decision problem with a strict success criterion: a mutated payload must "
        "both pass the WAF and extract the target data. Under a common training budget "
        "against ModSecurity CRS v3.3.2, TRPO achieved the highest observed union-corpus IFNR "
        "(99.1%) and the lowest SPBARC (6.07). The largest differences among TRPO, PPO, and "
        "A2C occurred on complex payloads requiring six- to seven-step mutation chains. "
        "Because this comparison used one seed per algorithm, the magnitude and stability of "
        "the ranking require multi-seed replication. On the error corpus, A2C achieved a "
        "mean IFNR of 22.3% with a standard deviation of 14.4 percentage points, compared "
        "with 2.3 for TRPO and 1.9 for PPO. This result shows that A2C performance was "
        "substantially more seed-sensitive in the evaluated setting. Pairwise reversal "
        "experiments also identified 35 directional mutation dependencies supported by at "
        "least two algorithms, including the unanimously supported newline → func_sp_nbsp "
        "pair. The strongest observed dependency, ident_backtick → hex_to_char, achieved "
        "98.0% success in the forward order and 0.0% in reverse."
    ),
    84: (
        "Policies trained against ModSecurity achieved an IFNR of 0% when transferred to "
        "SafeLine without additional training. Direct training against SafeLine allowed at "
        "least one request to pass the WAF in approximately 89% of episodes, but no episode "
        "successfully extracted data. These results show that WAF evasion and successful SQL "
        "execution must be measured separately. Future work should first develop mutation "
        "operators that preserve SQL syntax and semantics while exploring representations "
        "relevant to learning-based WAFs. It should then evaluate these operators across "
        "additional WAF products, versions, database backends, injection types, and random "
        "seeds. Learned payload representations and multi-target training may subsequently "
        "be investigated as methods for improving sample efficiency and cross-target "
        "transfer."
    ),
}


def paragraph_text(paragraph: ET.Element) -> str:
    return "".join(node.text or "" for node in paragraph.iter(W + "t")).strip()


def replace_text(paragraph: ET.Element, replacement: str) -> None:
    if any(True for _ in paragraph.iter(M + "oMath")):
        raise ValueError("Refusing to replace a paragraph containing a Word equation")

    text_nodes = list(paragraph.iter(W + "t"))
    if not text_nodes:
        raise ValueError("Cannot replace a paragraph without a text node")

    text_nodes[0].text = replacement
    text_nodes[0].set("{" + XML_NS + "}space", "preserve")
    for node in text_nodes[1:]:
        node.text = ""

    # Highlight the run containing the revised text so the changes are visible
    # when the document is opened in Word or another compatible editor.
    revised_run = None
    for run in paragraph.iter(W + "r"):
        if text_nodes[0] in list(run.iter(W + "t")):
            revised_run = run
            break
    if revised_run is None:
        raise ValueError("Could not locate the run containing the revised text")

    run_properties = revised_run.find(W + "rPr")
    if run_properties is None:
        run_properties = ET.Element(W + "rPr")
        revised_run.insert(0, run_properties)

    highlight = run_properties.find(W + "highlight")
    if highlight is None:
        highlight = ET.SubElement(run_properties, W + "highlight")
    highlight.set(W + "val", "yellow")


def main() -> None:
    if not SOURCE.is_file():
        raise FileNotFoundError(SOURCE)
    with ZipFile(SOURCE, "r") as source_zip:
        document_xml = source_zip.read("word/document.xml")
        root = ET.fromstring(document_xml)
        body = root.find(W + "body")
        if body is None:
            raise ValueError("DOCX document body was not found")

        nonempty_ordinal = 0
        changed = []
        for paragraph in body.findall(W + "p"):
            original = paragraph_text(paragraph)
            if not original:
                continue
            nonempty_ordinal += 1
            replacement = REPLACEMENTS.get(nonempty_ordinal)
            if replacement is None:
                continue
            replace_text(paragraph, replacement)
            changed.append(nonempty_ordinal)

        missing = sorted(set(REPLACEMENTS) - set(changed))
        if missing:
            raise RuntimeError(f"Expected paragraphs were not replaced: {missing}")

        updated_xml = ET.tostring(
            root, encoding="utf-8", xml_declaration=True
        )

        try:
            with ZipFile(TEMP_OUTPUT, "w", compression=ZIP_DEFLATED) as output_zip:
                for item in source_zip.infolist():
                    data = (
                        updated_xml
                        if item.filename == "word/document.xml"
                        else source_zip.read(item.filename)
                    )
                    output_zip.writestr(item, data)
            os.replace(TEMP_OUTPUT, OUTPUT)
        finally:
            if TEMP_OUTPUT.exists():
                TEMP_OUTPUT.unlink()

    print(f"Created {OUTPUT} with {len(changed)} rephrased paragraphs.")


if __name__ == "__main__":
    main()
