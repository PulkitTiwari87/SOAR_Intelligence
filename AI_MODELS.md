# AI models

Read this before trusting any score. **No labelled Wazuh incident data ships with this repository**, so every
model below is trained on synthetic or hand-written data, and the numbers are measured on that same kind of
data. They demonstrate that the mechanisms work and are reproducible; they are **not** estimates of production
accuracy. The dashboard (*AI & analysis*) shows the same figures straight from each model's `metadata.json`.

## Artifacts and integrity

`models/<name>/metadata.json` records version (`<schema>-<hash8>`), training-data provenance, features, evaluation,
limitations and a SHA-256 for each file. XGBoost is saved in its native JSON format (no pickle); scikit-learn
bundles use joblib **and are only loaded if the SHA-256 matches** (`ai/common.py`). Models are trained at image
build time (`python -m soar.cli train-models`), seeded, and retrained with the same command. Missing models are
trained on first use in development.

## ML triage (`ai/triage`) — XGBoost

Predicts the probability that a correlated alert set is *actionable*. Features: `rule_level`, `failed_logins`,
`src_ip_is_internal`, `ioc_score`, `ioc_known`, `event_count`, `is_fim_event`, `has_mitre_tag`, `off_hours`.
Each prediction includes the top-5 exact TreeSHAP contributions (log-odds). The label is a policy statement
("worth acting on"), so internet background scanning is labelled benign.

Training data: a scenario generator (6 malicious and 6 benign families with overlapping distributions and 3% label
noise). **The previous version derived features such as `src_ip_reputation` from the label and reported 100%
accuracy; that leakage is gone**, and `tests/test_ml.py` fails if any single feature separates the classes.

Evaluation on a held-out, independently seeded, distribution-shifted synthetic sample (6,000 rows):

| | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| XGBoost | 0.939 | 0.935 | 0.892 | 0.913 | 0.961 |
| Logistic regression (same features) | 0.885 | 0.874 | 0.791 | 0.830 | 0.935 |
| Rule `rule_level ≥ 10` | 0.781 | – | – | 0.624 | – |

5-fold CV ROC-AUC 0.961 ± 0.003, Brier 0.051. **Synthetic only.** Analyst decisions accumulate in `analyst_actions`;
`POST /api/ai/retrain` (admin) retrains with them (≥ 50 labels, ≥ 10 per class), weights them ×5, and **promotes the
candidate only if it beats the current model on held-out real labels** and does not regress on the synthetic hold-out.

## Anomaly detection (`ai/anomaly`) — Isolation Forest

Per-host behaviour metrics (events/min, failed auth, bytes, distinct ports, DNS, processes, file changes …).
`is_anomaly` = raw score above the 99th percentile of the model's own training baseline **or** any provided feature
≥ 6 baseline standard deviations away. The second rule exists because we measured that Isolation Forest scores
saturate for extreme out-of-range values (forest alone detected 33% of the synthetic attack profiles). Results
list which features deviated and which rule fired; defaulted features are reported. On synthetic data: 0.93% false
positives on a held-out baseline, 99.7% of the (hand-specified, extreme) synthetic attacks detected. Retrain on real
events with `train_model(baseline_df)`. `threat_type` is a rule-of-thumb hint, not a classifier output.

## Phishing (`ai/phishing`)

Score = 0.5 × text probability (TF-IDF + logistic regression) + 0.5 × indicator score. Indicators: IP-literal hosts,
punycode, risky TLDs, URL shorteners, `@` in URL, brand look-alike/embedded brand domains, link text ≠ target,
Reply-To mismatch, SPF/DKIM/DMARC failure, display-name brand impersonation. A strong text-only signal (BEC without
links) is escalated to *suspicious*. Output: score, verdict, indicators, top terms, URLs, domains, IOCs, and the
SHA-256 of the analysed input; the original email is preserved as event evidence. The text model is trained on 121
short, hand-written messages: 5-fold CV accuracy 0.893 / F1 0.881, **optimistic because the corpus is templated**.
Domain handling has no public-suffix list (common two-level suffixes only) and does not fetch URLs.

## Log clustering (`ai/clustering`)

Template normalisation (IPs, numbers, users, paths → placeholders), TF-IDF, KMeans with *k* chosen by silhouette. A
cluster is "unusual" if it holds ≤ 5% of events or contains high-severity events; clusters list the incidents they
touch and how many events are unattached. Lexical (not semantic) by design.

## Blast radius (`ai/blast_radius`)

Bounded BFS over `asset_links`; `risk = 100 · criticality/10 / hops`, a prioritisation heuristic rather than a
probability. Returns affected host, related hosts, services (protocol/port), users seen, ranked hosts and attack
paths, and graph data for the UI. With no inventory it says so instead of inventing a topology.

## LLM incident commander (`ai/llm_commander`)

Decision support only. Providers: `gemini`, `openai`, `anthropic`, `ollama`/`openai_compatible` (local models), via
plain HTTPS; keys come from the environment and are never logged or echoed. The model receives structured context
(incident, alerts, ML, intel, MITRE, assets, history, timeline) and must answer with JSON matching
`CommanderOutput` (summary, severity, confidence, MITRE techniques, evidence, recommended actions,
`requires_human_approval`). Output is schema-validated (one retry with the error), unknown ATT&CK ids are dropped,
recommended actions are limited to the action registry and each is annotated with the response-policy outcome; the
model cannot loosen approval requirements and has no execution path. Incident text is passed as *untrusted data*
with an instruction not to follow it, and the safety guarantee does not depend on the model obeying it. Without a
provider or key (or after invalid output) a deterministic analysis labelled `rule_based_fallback` is returned. Not
verified against a live provider in this repository (no key available); request shapes are tested with mock transports.

## Offline experiment

`ai/triage/train_soar2_model.py` is the earlier KDD Cup '99 multi-class experiment (needs `imbalanced-learn`,
downloads the dataset). It is **not wired into the platform** (KDD connection features do not exist in Wazuh alerts)
and was not run for this documentation, so no results are reported for it.
