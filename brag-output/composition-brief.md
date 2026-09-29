# Hyperframes Composition Brief: SOAR Intelligence

## Objective
Create a serious, cinematic 45–60s product showcase for SOAR Intelligence — a self-hosted, AI-assisted SOAR platform — built entirely from its real UI and real product claims. Not a generic launch sting; a technical documentary walkthrough of one real detection-to-response pipeline.

## Output
- Composition directory: `brag-output/composition/`
- Rendered video: `brag-output/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 55 seconds (explicit user override of the skill's default 15-25s range)

## Source Material
- Project root: `D:\Claude Code\SOAR_Intelligence`
- Primary files read: `README.md`, `PRODUCT.md`, `dashboard/frontend/src/index.css`, `dashboard/frontend/src/Layout.jsx`, `dashboard/frontend/src/pages/Overview.jsx`, `IncidentDetail.jsx`, `AIModels.jsx`, `Intel.jsx`, `Playbooks.jsx`
- Product name: SOAR Intelligence
- Tagline / strongest claim: "An AI-assisted Security Orchestration, Automation and Response platform you can run entirely on your own machine" — ingests events, correlates into incidents, scores risk, maps MITRE ATT&CK, enriches indicators, asks an LLM for decision support (advice only), runs policy-gated, human-approved, verified response playbooks.
- Key UI or visual moment to recreate: the Overview dashboard (stat cards, severity pie, Top ATT&CK bar chart, Latest Incidents table); Incident Detail (MITRE section, risk score breakdown, LLM analysis panel); AI & Analysis tabs (ML triage, anomaly detector); Threat Intel (enrichment bar + IOC table with verdict badges); Playbooks/Approvals (execution steps + pending human approval).
- Copy that must appear verbatim (from the real UI/README, not invented):
  - "From detection to actionable incidents"
  - "rule-based fallback (no LLM used)" (only if that is genuinely what a live run returns)
  - "DETECT · ANALYZE · ENRICH · RESPOND · AUTOMATE" (paraphrased from the README pipeline diagram: `sources → normalize → correlate → enrich → risk score → ... → playbook → verify → report`)
  - Nav labels exactly as shipped: Overview, Incidents, Approvals, Threat Intel, Assets, Playbooks, AI & Analysis, System, Admin

## Creative Direction
- Tone preset: cinematic
- Creative direction: restrained SOC product documentary — premium, technical, quiet confidence
- Interpretation: slow push-ins, precise crops, controlled motion; typography restrained (IBM Plex Sans/Mono, matching the product's own type system); transitions follow the real security workflow (detect → analyze → enrich → respond), never an arbitrary cinematic wipe
- Angle: one real pipeline run (the README's own documented `simulate brute_force` demo path), shown in the product's actual dark UI, ending with a human still deciding on the one action that needs approval
- Hook: near-black screen, faint dot-grid (from the login page background), a single command types in mono: `soar simulate brute_force`, hard cut to the dashboard
- Outro / punchline: settled Overview dashboard, small wordmark, `DETECT · ANALYZE · ENRICH · RESPOND · AUTOMATE`, fade to black
- Avoid:
  - Generic SaaS language ("streamline your workflow")
  - Cyberpunk/hacker-movie visual clichés (Matrix code, neon, glitch spam, skulls, hooded figures)
  - Abstract filler visuals unrelated to the actual screens
  - Fabricated metrics, incidents, or capabilities not present in the real UI/backend
  - Presenting synthetic ML metrics as production accuracy claims

## Visual Identity
- Background: `#16171B` (canvas) / `#131418` (sidebar) / `#1E1F25` (card)
- Text: `#E2E3E8` primary / `#9B9CA5` secondary / `#727785` muted
- Accent: `#9B98B8` (accent), `#B0ADCC` (accent hover)
- Severity/status colors (functional only): critical `#C0392B`, high `#A0522D`, warning `#8B7355`, success `#4A7C59`, info `#4A7C8C`
- Display + UI font: IBM Plex Sans (self-hosted at `dashboard/frontend/public/fonts/`); data/mono font: IBM Plex Mono
- Visual references from the project: `dashboard/frontend/src/index.css` design tokens (`:root` custom properties), `.stat-card`, `.badge-*`, `.ioc-verdict`, `.ai-model-block`, `.login-page` dot-grid background, sidebar/topbar chrome

## Storyboard
Use the storyboard in `brag-output/brag-plan.md` as the creative contract (full detail, including per-scene audio-coupled moments, is there — do not restate loosely here).

Scene summary:
1. Opening — 5s — dot-grid + typed command `soar simulate brute_force`, hard cut to dashboard
2. SOC overview — 7s — Overview dashboard: stat cards, severity pie, Top ATT&CK chart, new incident row landing
3. Detection to incident — 7s — Incident Detail: MITRE ATT&CK populating, risk score breakdown
4. AI/ML analysis — 8s — AI & Analysis tabs: ML triage, anomaly detector, "Run LLM analysis" result
5. Threat intelligence — 7s — Threat Intel: enrichment form submit, IOC verdict badge landing
6. Automated response — 8s — Playbooks execution (verified steps) + Approvals pending human decision
7. End-to-end montage — 8s — rapid cuts across all screens above, words DETECT→ANALYZE→ENRICH→RESPOND→AUTOMATE
8. Final product shot — 5s — settled Overview dashboard, wordmark, pipeline line, fade to black

## Audio
- Audio role: cinematic support, restrained low-frequency presence
- Audio arc: near-silent under the opening typed command → steady build through dashboard/incident/analysis/enrichment → fullest (still controlled) energy under the response/automation montage → pulls back for the final shot and fade
- Music: **limitation note** — the ideal direction is a dark atmospheric industrial-electronic bed, but the only bundled `/brag` music library is the "Happy Beats / Business Moves" set (upbeat, corporate-adjacent; no industrial/dark track exists in the asset library). Closest available fit: `happy-beats-business-moves-vol-12-by-ende-dot-app.mp3` ("steady and clean," documented as best for `polished`/`cinematic`). Use it at a low, restrained volume (~0.20-0.25, toward the deadpan/restraint end of the documented range) rather than its default energetic level, so it reads as a quiet bed rather than upbeat corporate music. This is an honest substitution, not the originally-specified sound — flag it to the user in the final delivery notes.
- Music treatment: fade in low under scene 1, sustained low build through scenes 2-5, slightly fuller (still low, never above ~0.3) through scenes 6-7, fade further under scene 8's wordmark; no drop
- Music cue guidance: bundled preset exists at `assets/music/cues/happy-beats-business-moves-vol-12-by-ende-dot-app.music-cues.{json,md}` — read it for tempo/strongCues/beats; target strong-cue locks near ~0:05 (cut to dashboard), ~0:19 (AI analysis reveal), ~0:42 (response/montage entry) only where they don't hurt readability
- Audio-reactive treatment: subtle — bass/RMS may very slightly modulate an existing UI glow or the topbar live-feed pulse dot; never waveform bars or overt reactivity
- Audio-coupled moments:
  - Scene 1 — typed command with soft key ticks, low system pulse building
  - Scene 2 — stat cards arriving one by one, firmer tone on new incident row landing
  - Scene 3 — light ticks as MITRE chips populate
  - Scene 4 — confirmation tone when "Run LLM analysis" result badge appears
  - Scene 5 — type-in on enrichment field, distinct tone on verdict badge arrival
  - Scene 6 — step-check tick per verified playbook step, calmer distinct tone on the pending-approval highlight
  - Scene 7 — each DETECT/ANALYZE/ENRICH/RESPOND/AUTOMATE word-swap on a beat
  - Scene 8 — bed resolves quietly, no final "drop"
- SFX selection guidance: sparse, professional — soft UI clicks, quiet confirmation tones, no hacker beeps/alarms/arcade sounds
- SFX analysis guidance: use `sfx-analysis.md` if present; prefer low high-frequency-risk sounds for repeated/polished moments (card arrivals, badge landings)
- Exact SFX choice: Hyperframes chooses exact filenames/timestamps/density/volume once the animation is implemented
- Audio files: copy chosen music and any selected SFX into `brag-output/composition/assets/`

## Hyperframes Instructions
Load the composition-building Hyperframes domain skills — `hyperframes-core`, `hyperframes-animation`, `hyperframes-creative`, `hyperframes-keyframes`, `hyperframes-cli`. `/brag` is its own workflow: do not enter the `hyperframes` entry-point intent interview and do not route into its generic promo/launch-video workflow. Prefer native Hyperframes conventions over anything stated loosely above.

Requirements:
- Show real UI/copy from the source project (the dashboard screens listed above), not abstract filler.
- Keep all text readable in the final render (respect the reading-time floor from `step-2-plan.md`).
- Duration is 55 seconds (explicit override — do not force back to 15-25s).
- Include the planned music/SFX layer.
- Treat audio notes above as guidance, not a fixed cue sheet; choose SFX after the visual animation exists.
- Use only 1-3 strong-cue locks across the whole video.
- When music is present, consider the audio-reactive workflow for one subtle element; skip and document if extraction is unavailable.
- Use local self-hosted assets only (no external font/script CDNs) — this matches the real product's own CSP constraint.
- Run `hyperframes check` before render — it is brag's single gate.
