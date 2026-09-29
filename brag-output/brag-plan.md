# Brag Plan: SOAR Intelligence

## What is this app?
A self-hosted SOAR platform that turns raw security events into correlated, risk-scored incidents — enriched with ML triage, anomaly detection, MITRE ATT&CK mapping and threat intel, advised (not decided) by an LLM commander, and resolved through policy-gated, human-approved, verified response playbooks.

## The angle
This is not a marketing site — it is a real operator tool an analyst lives in for a shift. The angle is a technical documentary walkthrough of one real pipeline, in the product's own real UI: an event becomes an incident, the incident gets machine-reasoned about with visible evidence (not just a verdict), and a human stays in the loop before anything executes. No invented numbers, no invented incidents — whatever is on screen must be something the app actually renders.

## Hook (first 2-3 seconds)
Near-black screen, faint dot-grid background (the app's own login-page grid pattern). A single line of IBM Plex Mono types in: `soar simulate brute_force`. Cut hard to the Overview dashboard as its stat cards populate. No logo yet — the product's own dark UI is the first thing seen.

## Key moments (the middle)
- Overview dashboard: stat cards (Critical, Active incidents, Alerts today, Automated responses, MTTD, MTTR) plus the severity pie chart and Top ATT&CK bar chart, with a new row landing in "Latest incidents."
- Incident Detail: MITRE ATT&CK section populating, the risk score breakdown, and the "Run LLM analysis" action producing a labeled result (either a live LLM call or the honestly-badged "rule-based fallback (no LLM used)" — whichever the running instance actually returns).
- Threat Intel: the enrichment bar (type + value + Enter) submitting an indicator, and the IOC table showing a verdict badge (malicious/suspicious/benign/unknown) with provider and confidence.
- Playbooks: an execution row with per-step verification, next to Approvals showing a pending human decision (e.g. `block_ip`) waiting for a person — the platform refusing to act alone.

## Outro / punchline
Return to the Overview dashboard, now fully populated, held for a beat. Wordmark "SOAR INTELLIGENCE" appears small and restrained, followed by the pipeline line already used in the README: `DETECT · ANALYZE · ENRICH · RESPOND · AUTOMATE`. Fade to black. No slogan beyond that.

## User flow worth showing
1. **Entry** — run the documented simulator (`python -m soar.cli simulate brute_force`) against a running instance; this is the project's own documented demo path, not a fabricated scenario.
2. **Key action** — the resulting incident is opened: MITRE mapping, risk score breakdown, and ML/LLM analysis are inspected; an indicator from the incident is enriched in Threat Intel.
3. **Result** — the incident's low-risk playbook steps show as already executed and verified, and the one action requiring a human (e.g. isolate/block) sits in Approvals, unexecuted, waiting.

This is the centerpiece. Landing-page-style stat/logo cards appear only as light framing (open + close), never as a substitute for the flow above.

## Tone
- Preset: cinematic
- Creative direction: "restrained SOC product documentary" — premium, technical, quiet confidence. Explicitly not cyberpunk, not hacker-movie, no neon/glitch/Matrix-code/skulls.
- Interpretation: wide, settled shots of the real UI with slow push-ins and precise crops rather than fast chaotic cuts; typography is minimal and functional (IBM Plex, matching the app's own type system); every transition follows the actual security workflow (detect → analyze → enrich → respond), never an unrelated cinematic wipe.

## Format: landscape — 1920x1080
## Duration: 55s (user specified 45-60s; overrides the default 15-25s auto range)

## Visual identity (from the project)
- Background: `#16171B` (canvas), `#131418` (sidebar), `#1E1F25` (cards)
- Accent: `#9B98B8` (lightened violet-gray, the product's interactive/selection color)
- Text: `#E2E3E8` primary / `#9B9CA5` secondary
- Severity/status (only functional colors allowed beyond the base palette): critical `#C0392B`, high `#A0522D`, warning `#8B7355`, success `#4A7C59`, info `#4A7C8C`
- Display + UI font: IBM Plex Sans (self-hosted, `Plex Sans`); data/mono font: IBM Plex Mono (`Plex Mono`) — used for the hook's typed command line and all timestamp/ID/mono chrome, matching the app's own convention
- Strongest visual element: the dark, restrained dashboard itself — stat cards, severity pie, and the honest badge language ("rule-based fallback (no LLM used)", synthetic-data disclosures) that signals this is a real trust-earning tool, not a template

## Share copy (draft)
"SOAR Intelligence: event → correlated incident → ML/LLM-assisted triage → threat intel → policy-gated, human-approved response. Self-hosted, open, and honest about what's synthetic."

## Audio direction
- Role: cinematic support with restrained low-frequency presence
- Music: dark atmospheric industrial-electronic bed — sub-bass pulse, controlled percussion, no drop, gradual escalation toward the response/automation scenes then falling back for the final shot
- Music treatment: near-silent opening under the typed command, slow build through the dashboard/incident scenes, fullest (still controlled) energy under the response/montage scene, pulled back for the final product shot and fade
- Music cue guidance: to be detected/selected at composition time (no bundled preset assumed); target one strong cue at the hard cut into the dashboard (~0:05), one at the incident-analysis reveal (~0:19), and one at the response/automation montage entry (~0:42)
- Audio-reactive treatment: subtle — bass/RMS may very slightly modulate a UI glow or the topbar "live feed" pulse dot that already exists in the product; never waveform bars or overt reactivity
- SFX posture: sparse, professional — soft UI clicks, a quiet confirmation tone on badge/approval reveals, a low system pulse under the typed command; no hacker beeps, no alarms
- Audio-coupled moments: the typed `soar simulate brute_force` command (soft key ticks), stat cards arriving one by one on Overview, the IOC verdict badge landing, the approval row appearing
- Restraint rule: never louder or busier than the UI itself; music must never imply drama the product doesn't claim

## Storyboard

### Scene 1 — Opening — 5s
Near-black, faint dot-grid (from the app's own login background). `soar simulate brute_force` types in IBM Plex Mono, character by character. Hard cut to the Overview dashboard loading.
Sequential/interaction: yes — command types out character by character, then a hard cut.
Audio intent: quiet tension, anticipation.
Audio-coupled idea: typed text with subtle key ticks; a low system pulse begins under the last few characters.
Music: near-silent atmospheric bed, just starting.
Transition mood: hard cut → Scene 2

### Scene 2 — SOC overview — 7s
Overview dashboard. Slow push-in as stat cards (Critical, Active incidents, Alerts today, Automated responses, MTTD, MTTR) arrive one by one, then the severity pie and Top ATT&CK bar chart settle in, then a new row lands in "Latest incidents."
Text: "One operational picture for the SOC" (small, restrained).
Sequential/interaction: yes — stat cards arrive one by one, then the new incident row lands in the table.
Audio intent: build, quiet confidence.
Audio-coupled idea: soft card-arrival ticks; a slightly firmer confirmation tone when the new incident row lands.
Music: bed builds under the reveal.
Transition mood: clean crossfade → Scene 3

### Scene 3 — Detection to incident — 7s
Cut/track into the new incident's detail view: severity + status badges, risk score breakdown with per-signal availability, MITRE ATT&CK techniques populating.
Text: "From detection to actionable incidents"
Sequential/interaction: yes — MITRE technique chips and risk-score signal rows populate in sequence.
Audio intent: focus, precision.
Audio-coupled idea: light ticks as MITRE chips populate.
Music: continues building, restrained percussion enters.
Transition mood: soft wipe → Scene 4

### Scene 4 — AI/ML analysis — 8s
"AI & Analysis" tab: ML triage block (feature contributions), Anomaly detector block, and the incident's "Run LLM analysis" producing its labeled result — shown honestly, including the rule-based-fallback badge if that's what the live instance returns.
Text: "AI-assisted investigation" then "Every signal is explainable."
Sequential/interaction: yes — cursor clicks "Run LLM analysis"; the labeled result card arrives.
Audio intent: analytical, deliberate.
Audio-coupled idea: a single confirmation tone when the analysis result badge appears.
Music: mid-energy, controlled.
Transition mood: crossfade → Scene 5

### Scene 5 — Threat intelligence — 7s
Threat Intel page: an indicator is entered into the enrichment bar and submitted; the IOC table gains a row with its verdict badge (malicious/suspicious/benign — whatever the live enrichment actually returns), provider and confidence.
Text: "Enrich every signal with context"
Sequential/interaction: yes — enrichment form submits, new IOC row appears with its verdict badge landing last.
Audio intent: connective, contextual.
Audio-coupled idea: soft type-in on the enrichment field; a distinct tone on verdict-badge arrival.
Music: sustains mid-energy.
Transition mood: clean wipe → Scene 6

### Scene 6 — Automated response — 8s
Playbooks page: an execution row with verified steps, then Approvals showing the one pending human decision (e.g. `block_ip`) still waiting.
Text: "Coordinated response — human-approved"
Sequential/interaction: yes — playbook step rows check off one by one; approval row is highlighted, unexecuted.
Audio intent: highest controlled energy of the video, but still restrained industrial, not aggressive.
Audio-coupled idea: a step-check tick per verified step; a distinct, calmer tone (not an alarm) on the pending-approval highlight, reinforcing "a human decides."
Music: fullest (still controlled) energy point.
Transition mood: hard cut → Scene 7

### Scene 7 — End-to-end montage — 8s
Fast but readable cuts across the real screens already shown, in pipeline order: Overview → Incident Detail → AI & Analysis → Threat Intel → Playbooks/Approvals, each held long enough to register.
Text (sequential, one word replacing the last): "DETECT" → "ANALYZE" → "ENRICH" → "RESPOND" → "AUTOMATE"
Sequential/interaction: yes — five words replace each other in time with five screen cuts.
Audio intent: propulsive but controlled, arriving somewhere rather than escalating forever.
Audio-coupled idea: each word-swap lands on a beat.
Music: sustains near-peak, begins to settle by the end of the scene.
Transition mood: hard cuts throughout → Scene 8

### Scene 8 — Final product shot — 5s
Return to the Overview dashboard, now fully populated, slow settle (motion stops). "SOAR INTELLIGENCE" wordmark appears small, bottom-restrained, then the line "DETECT · ANALYZE · ENRICH · RESPOND · AUTOMATE" beneath it. Fade to black.
Sequential/interaction: none — a single settle and two text reveals.
Audio intent: resolution, quiet confidence.
Audio-coupled idea: none beyond the bed resolving; no final "drop."
Music: pulls back, gentle fade under the wordmark.
Transition mood: fade to black (end)

**Music mood for this video:** cinematic — dark atmospheric industrial-electronic, gradual escalation, no drop, controlled resolution.
**Audio summary:** The bed starts near-silent under a typed command, builds steadily through detection/analysis/enrichment, reaches its fullest but still restrained energy under the response/automation montage, then settles for a quiet final shot — sound tracking "security infrastructure operating under pressure," never spectacle for its own sake.
