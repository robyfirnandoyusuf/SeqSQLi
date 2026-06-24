# Presentation Notes — SeqSQLi
# Speaker script per slide (English)
# Total time: ~15 min presentation + 5–10 min Q&A

---

## Slide 1 — Title (~30 sec)

"Good morning, everyone.
My name is Roby Firnando Yusuf.
Today I will present my research on SeqSQLi —
a framework that uses Deep Reinforcement Learning to automatically
find sequences of SQL payload mutations that bypass Web Application Firewalls.
Let's get started."

---

## Slide 2 — Agenda (~15 sec)

"This presentation has five parts:
background and motivation, the SeqSQLi framework,
experimental setup, results and analysis,
and conclusions with future directions."

---

## Slide 3 — Background (~1 min)

"SQL Injection still appears in the OWASP Top 10 in 2025.
An attacker injects SQL commands into inputs that the application
passes directly to the database — for example, a login form.

Web Application Firewalls are the primary defense:
they scan incoming requests and block anything matching a known pattern.

The fundamental weakness is that WAFs check the TEXT of the request,
not what it actually does to the database.
So if we change how the SQL looks while keeping its meaning intact,
the WAF may not recognize the threat.

Simple example: SELECT can be written as SeLeCt.
The database executes them identically. The WAF pattern does not match."

---

## Slide 4 — Motivation (~1 min)

"Prior approaches to WAF bypass share common limitations.
Random mutation fires blindly without learning.
Grammar-based systems generate variants but don't learn from WAF responses.
And no prior work formally studied whether the ORDER of mutations matters.

SeqSQLi fills all three gaps.
The agent receives direct feedback from the live WAF on every attempt
and learns which sequences of mutations are most effective.

We are also the first to formally analyze mutation ordering as a signal —
and that signal turns out to be real and structurally significant."

---

## Slide 5 — Framework (~1.5 min)

"This diagram shows the SeqSQLi pipeline as a Markov Decision Process.

At each step, the agent observes the current state — a 67-number vector.
It selects one of 51 mutation operators.
The mutated payload is sent as an HTTP request to the live WAF.
The WAF responds: 200 OK for success, or 403 blocked.
This becomes the reward signal.
The agent updates its policy and tries again.

Each episode starts with one payload, runs for at most 15 steps,
and ends early if the WAF is successfully bypassed."

---

## Slide 6 — State Representation (~1 min)

"The agent perceives the world through 67 numbers.

14 numbers: a checklist of whether each mutation family has already been applied.

1 number: a task type bit distinguishing union from error-based injection.
Without this, the agent confuses two tasks and the policy collapses.

51 numbers: one-hot encoding of the last action taken.
This is the key component for ordering — the agent can reason:
I just applied case mixing, so next I should try whitespace encoding.

1 number: step fraction — gives the agent an implicit remaining-budget signal."

---

## Slide 7 — Action Space (~1 min)

"The agent can choose from 51 operators in 9 families.

The critical invariant: ALL operators preserve SQL semantics.
The mutated payload executes identically on the database.
Only the text representation changes.

The most impactful addition is aggregate swap —
replacing GROUP_CONCAT with JSON_ARRAYAGG(CONCAT(...)).
This single mutation unlocked bypass on the complex tier,
which was previously at zero percent."

---

## Slide 8 — Reward Function (~45 sec)

"Seven possible outcomes, ranging from +10 to -3.

Plus ten only when the WAF is genuinely bypassed with canary markers confirmed.

STAGNANT gets the lowest reward — minus three — to prevent a do-nothing policy.

PBRS adds a bonus each time the agent removes a WAF trigger from the payload.
This provides dense intermediate guidance.
Critically, it does not change the optimal policy —
guaranteed by the telescoping property proven by Ng et al. 1999."

---

## Slide 9 — Algorithms (~1.5 min)

"We compare three on-policy RL algorithms.

PPO clips the probability ratio to prevent large updates — a soft brake.

TRPO enforces a hard KL-divergence bound, guaranteeing each update
does not degrade performance.
This is especially valuable in sparse-reward, long-horizon problems.

A2C applies gradients directly with no constraint — simplest but most unstable.

All three share the same network, training budget, and environment.
Any performance difference is attributable purely to the update mechanism."

---

## Slide 10 — Experimental Setup (~45 sec)

"All three algorithms are evaluated under identical conditions.

Target: ModSecurity CRS v3.3.2 behind nginx, protecting sqli-labs Less-1.

The 108 payloads are split into three tiers based on how many
WAF rule families must be defeated simultaneously:
Trivial — keyword-casing and whitespace.
Medium — plus aggregate function rules.
Complex — plus hex encoding and bare table reference rules.

All payloads are validated against the raw backend before training."

---

## Slide 11 — Results Table (~1.5 min)

"TRPO leads with 99.1% IFNR — 107 out of 108 originally blocked payloads
are now successfully bypassed, using an average of only 6.07 requests.

PPO follows at 88.9%, A2C at 76.9%.
All three vastly outperform the random baseline at 3.7%.

But the overall numbers don't tell the full story.
Look at the Complex column — that is where the three algorithms truly diverge.
97.2%, 66.7%, 33.3%.
This is the most important finding in the table."

---

## Slide 12 — Tier Analysis (~1 min)

"The bar chart makes this unmistakable.

Trivial and medium: all bars near 100% — these tiers are easy.

Complex: TRPO 97.2%, PPO 66.7%, A2C only 33.3%.

Complex payloads require three or more mutations in the correct order,
each targeting a different WAF rule family simultaneously.
A single wrong ordering breaks the entire sequence.

This is where TRPO's hard KL constraint pays off —
it prevents the catastrophic updates that would destroy a
partially-learned long mutation chain."

---

## Slide 13 — Training Curves (~45 sec)

"TRPO converges to the highest reward with the most stable trajectory.

PPO rises faster early on but plateaus below TRPO.

A2C shows a policy collapse at around 80,000 timesteps —
a dramatic drop caused by an unconstrained update destroying the
policy that was already being learned.
A2C recovers partially but never reaches TRPO or PPO levels."

---

## Slide 14 — Ordering Analysis (~1.5 min)

"This is our second original finding.

We analyzed action-pair frequencies from all training logs.
For every pair A then B, we ask: what happens if reversed to B then A?
If the success rate drops by more than 10 points, the pair is ordering-dependent.

Result: 35 consensus pairs — ordering-dependent in at least 2 of 3 algorithms.

Most extreme example: ident_backtick then hex_to_char.
Forward: 98% success. Reversed: 0%.

Why? hex_to_char converts character tokens to hex,
corrupting the identifier token before ident_backtick can wrap it.
Apply hex first — the backtick mutation has nothing valid to work with.

The key insight: this pattern is identical across three different algorithms.
This proves the dependency originates from the WAF rule structure itself,
not from any single algorithm's learning dynamics."

---

## Slide 15 — Conclusion (~1 min)

"Four takeaways.

First: RL effectively learns WAF bypass. TRPO achieves 99.1%.

Second: TRPO outperforms PPO and A2C.
The hard KL-bound constraint is the key advantage for sparse-reward,
long-horizon problems.

Third: mutation ordering is a real, learnable structural signal.
35 consensus pairs confirm it reflects WAF rule topology.

Fourth: the complex tier is the true benchmark.
Trivial and medium are saturated — complex reveals real capability differences."

---

## Slide 16 — Limitations & Future Work (~45 sec)

"We tested a single WAF with a single injection type and application.
Generalizability has not been verified.

The most exciting next step is RQ2:
can the policy trained on ModSecurity transfer to Safeline CE —
an ML-based WAF using a neural network instead of regex rules —
without any retraining?
This zero-shot transfer is the core of our upcoming publication."

---

## Slide 17 — Closing (~15 sec)

"That concludes my presentation.
Thank you for your attention.
I am happy to take questions."

---

## Anticipated Q&A

**Q: Why ModSecurity specifically?**
A: It is one of the most widely deployed open-source WAFs with a well-documented,
reproducible rule set — ideal for a controlled baseline before testing on
commercial or ML-based WAFs.

**Q: How is PBRS different from changing the reward?**
A: PBRS adds a shaping term that telescopes to zero over a full episode,
leaving the set of optimal policies unchanged. Proven by Ng et al. 1999.
It only makes the learning signal denser, not different in direction.

**Q: Why not include Safeline in this paper?**
A: Safeline is the planned RQ2 for the publication paper.
This work first establishes the RL baseline on ModSecurity
before measuring the cross-WAF transfer gap.

**Q: Could this framework be misused?**
A: All experiments run in an isolated local lab with no external targets.
The intended use cases are security research and penetration testing —
the same as existing tools like sqlmap. The generated payloads can also
be used defensively to improve WAF rules.

**Q: What does SPBARC stand for?**
A: Successful Payload Bypass Average Request Count.
It measures inference efficiency — requests needed per successful bypass.
TRPO's 6.07 versus A2C's 10.08 means TRPO is roughly 40% more efficient.
