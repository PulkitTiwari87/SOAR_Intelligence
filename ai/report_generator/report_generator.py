#!/usr/bin/env python3
"""
Module 3.8: Incident Report Generator
========================================
Automatically generates professional, detailed PDF incident reports.
Reports are written so that ANYONE — technical or non-technical — can
understand what happened, using proper security terminology with
plain-English explanations alongside each technical term.

The report includes:
  1. Executive Summary (what happened in simple terms)
  2. What Is This Attack? (explains the attack type)
  3. Affected Device Details
  4. Threat Intelligence (MISP matches + what they mean)
  5. AI Analysis Scores (ML Triage, Anomaly, Blast Radius)
  6. Indicators of Compromise (IOCs)
  7. Step-by-Step Timeline (what the system did automatically)
  8. Impact Assessment (what could have happened if not stopped)
  9. Recommendations (what to do next)
  10. Glossary (defines every technical term used)
"""

import json
import os
import sys
from datetime import datetime

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.lib.colors import HexColor
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, ListFlowable, ListItem
    )
except ImportError:
    os.system("pip install reportlab")
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.lib.colors import HexColor
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, ListFlowable, ListItem
    )

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "reports")

# ─── Color Palette ───
NAVY       = HexColor('#1a1a2e')
DARK_BLUE  = HexColor('#16213e')
ACCENT     = HexColor('#0f3460')
RED        = HexColor('#e94560')
GREEN      = HexColor('#2ecc71')
ORANGE     = HexColor('#f39c12')
GREY       = HexColor('#666666')
LIGHT_GREY = HexColor('#f0f0f5')
WHITE      = HexColor('#ffffff')
BORDER     = HexColor('#cccccc')

# ─── Attack Explanations (plain English + technical) ───
ATTACK_EXPLANATIONS = {
    "SSH Brute Force": (
        "An attacker repeatedly tried to guess the login password of this device using thousands "
        "of common password combinations. This is called a <b>Brute Force Attack</b> "
        "(MITRE ATT&CK: T1110). Think of it like someone trying every possible key on a lock "
        "until one fits. The attack targeted the <b>SSH service</b> (Secure Shell), which is used "
        "for remote command-line access to servers."
    ),
    "Ransomware": (
        "A malicious program (malware) was detected encrypting files on this device. "
        "<b>Ransomware</b> (MITRE ATT&CK: T1486) locks your files with a secret key and demands "
        "payment (usually in cryptocurrency) to unlock them. Without the key, the files become "
        "unreadable. This is one of the most destructive types of cyberattacks."
    ),
    "Data Exfiltration": (
        "Sensitive data was detected being transferred outside the network to an unauthorized "
        "destination. This is called <b>Data Exfiltration</b> (MITRE ATT&CK: T1041) — essentially "
        "digital theft. The attacker may have stolen confidential documents, credentials, or "
        "personal data by uploading them to an external server."
    ),
    "C2 Beacon": (
        "This device was communicating with a <b>Command &amp; Control (C2) server</b> "
        "(MITRE ATT&CK: T1071). A C2 server is a remote computer controlled by an attacker that sends "
        "instructions to infected devices. The device was 'phoning home' at regular intervals "
        "(called beaconing), indicating it may be under remote control by a threat actor."
    ),
    "Lateral Movement": (
        "After compromising one device, the attacker attempted to move to other devices on the "
        "same network. This is called <b>Lateral Movement</b> (MITRE ATT&CK: T1021). Imagine a "
        "burglar who breaks into one room and then walks through corridors to reach other rooms — "
        "that is what happened digitally across our network."
    ),
    "Phishing": (
        "A fraudulent email designed to trick an employee into revealing passwords or clicking a "
        "malicious link was detected. <b>Phishing</b> (MITRE ATT&CK: T1566) is social engineering — "
        "the attacker pretends to be someone trustworthy (like IT, HR, or a CEO) to deceive the target."
    ),
    "Privilege Escalation": (
        "The attacker attempted to gain higher-level permissions (like admin/root access) on this "
        "device. <b>Privilege Escalation</b> (MITRE ATT&CK: T1068) is like a regular employee "
        "finding a way to grant themselves manager-level access to systems they shouldn't control."
    ),
    "Web Attack": (
        "The attacker sent specially crafted requests to a web application to exploit a vulnerability. "
        "Common techniques include <b>SQL Injection</b> (inserting database commands into web forms) "
        "and <b>Cross-Site Scripting / XSS</b> (injecting malicious scripts). These attacks target "
        "websites and web-based applications (MITRE ATT&CK: T1190)."
    ),
}

DEFAULT_EXPLANATION = (
    "A security event was detected on this device that does not match normal operating patterns. "
    "The automated detection systems flagged this activity as potentially malicious based on its "
    "behavioral characteristics. Further investigation determined the appropriate response."
)


def get_attack_explanation(attack_type: str) -> str:
    """Get a plain-English explanation of the attack type."""
    for key, explanation in ATTACK_EXPLANATIONS.items():
        if key.lower() in attack_type.lower():
            return explanation
    return DEFAULT_EXPLANATION


def get_severity_details(severity: int) -> dict:
    """Return color, label, and description for severity levels."""
    mapping = {
        1: {"label": "LOW", "color": GREEN, "meaning":
            "Minor security event with limited risk. No immediate action required."},
        2: {"label": "MEDIUM", "color": ORANGE, "meaning":
            "Moderate risk event. Should be reviewed by the security team within 24 hours."},
        3: {"label": "HIGH", "color": ORANGE, "meaning":
            "Serious security event. Immediate review and potential containment required."},
        4: {"label": "CRITICAL", "color": RED, "meaning":
            "Active attack in progress or confirmed breach. Requires immediate automated and manual response."},
    }
    return mapping.get(severity, mapping[2])


def get_llm_analysis(case_data: dict) -> str:
    """Get AI-powered analysis from Gemini (falls back to detailed template)."""
    api_key = os.environ.get("GEMINI_API_KEY", "")

    if api_key and api_key != "YOUR_GEMINI_API_KEY":
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-2.0-flash")
            prompt = f"""You are a senior Security Operations Center (SOC) analyst writing an incident report
for a mixed audience of technical staff and non-technical management. Analyze this incident and provide:

1. EXECUTIVE SUMMARY (3-4 sentences, plain English, explain what happened and the outcome)
2. TECHNICAL ROOT CAUSE (what vulnerability or misconfiguration allowed this)
3. BUSINESS IMPACT (what could have happened if the attack succeeded)
4. RECOMMENDATIONS (5 specific, actionable steps to prevent recurrence, numbered)

Use professional security language but explain technical terms in parentheses.
Incident data:
{json.dumps(case_data, indent=2)}"""
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            pass

    # Fallback: detailed template-based analysis
    sev = get_severity_details(case_data.get("severity", 2))
    attack = case_data.get("attack_type", "Security Event")
    host = case_data.get("agent_name", "an endpoint")
    score = case_data.get("triage_score", "N/A")

    return (
        f"EXECUTIVE SUMMARY\n"
        f"A {sev['label'].lower()}-severity {attack} was detected on the device "
        f"'{host}'. The AI-powered SOAR (Security Orchestration, Automation, and Response) "
        f"pipeline automatically analysed the threat, cross-referenced it with global threat "
        f"intelligence databases, and executed the appropriate containment action within seconds. "
        f"The ML Triage model assigned a confidence score of {score}%, confirming this was a "
        f"genuine threat rather than a false alarm.\n\n"
        f"TECHNICAL ROOT CAUSE\n"
        f"The attack exploited an exposed network service that was accessible from external "
        f"IP addresses. The affected device had default or weak authentication settings, making "
        f"it vulnerable to automated attack tools. Network segmentation (dividing the network into "
        f"isolated zones) was insufficient to prevent the attacker from reaching internal services.\n\n"
        f"BUSINESS IMPACT (IF NOT STOPPED)\n"
        f"Had this attack not been detected and blocked automatically, the attacker could have:\n"
        f"- Gained unauthorized access to the device and any data stored on it\n"
        f"- Used the compromised device as a launchpad to attack other systems on the network\n"
        f"- Stolen sensitive data including credentials, documents, or customer information\n"
        f"- Installed persistent malware (backdoors) for long-term unauthorized access\n"
        f"- Caused significant downtime, financial loss, and reputational damage\n\n"
        f"RECOMMENDATIONS\n"
        f"1. Enforce strong password policies — require minimum 14 characters with mixed case, "
        f"numbers, and symbols on all remote-access services\n"
        f"2. Implement Multi-Factor Authentication (MFA) — add a second verification step "
        f"(like a phone code) so stolen passwords alone are not enough\n"
        f"3. Apply network segmentation — isolate critical servers (databases, domain controllers) "
        f"so compromised workstations cannot directly reach them\n"
        f"4. Update firewall rules — block the attacker's IP range and enable geo-blocking for "
        f"countries where the organization has no legitimate business\n"
        f"5. Enable enhanced monitoring — increase logging and alerting on all devices that were "
        f"within the blast radius (neighbouring devices at risk)"
    )


def _make_table(data, col_widths, header=False) -> Table:
    """Helper to create a styled table."""
    t = Table(data, colWidths=col_widths)
    style = [
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER),
        ('BACKGROUND', (0, 0), (0, -1), LIGHT_GREY),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]
    if header:
        style = [
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER),
            ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]
    t.setStyle(TableStyle(style))
    return t


def generate_pdf_report(case_data: dict, output_path: str = None) -> str:
    """Generate a comprehensive, detailed PDF incident report."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    incident_id = case_data.get("incident_id", f"IR-{datetime.now().strftime('%Y-%m%d-%H%M')}")
    if output_path is None:
        output_path = os.path.join(REPORTS_DIR, f"{incident_id}.pdf")

    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            topMargin=18*mm, bottomMargin=18*mm,
                            leftMargin=18*mm, rightMargin=18*mm)

    styles = getSampleStyleSheet()

    # ── Custom Styles ──
    title_style = ParagraphStyle('CTitle', parent=styles['Title'],
        fontSize=24, textColor=NAVY, spaceAfter=4, leading=28)
    subtitle_style = ParagraphStyle('CSubtitle', parent=styles['Normal'],
        fontSize=11, textColor=GREY, spaceAfter=2)
    heading_style = ParagraphStyle('CHeading', parent=styles['Heading2'],
        fontSize=13, textColor=DARK_BLUE, spaceBefore=14, spaceAfter=6,
        borderWidth=1, borderColor=ACCENT, borderPadding=5)
    body_style = ParagraphStyle('CBody', parent=styles['Normal'],
        fontSize=9.5, leading=14, alignment=TA_JUSTIFY)
    bold_body = ParagraphStyle('CBoldBody', parent=body_style,
        fontName='Helvetica-Bold')
    note_style = ParagraphStyle('CNote', parent=styles['Normal'],
        fontSize=8.5, leading=12, textColor=GREY, leftIndent=12,
        borderWidth=0.5, borderColor=BORDER, borderPadding=6,
        backColor=HexColor('#f8f8fc'))
    footer_style = ParagraphStyle('CFooter', parent=styles['Normal'],
        fontSize=7.5, textColor=GREY, alignment=TA_CENTER)
    glossary_term = ParagraphStyle('GTerm', parent=styles['Normal'],
        fontSize=9, fontName='Helvetica-Bold', leading=12)
    glossary_def = ParagraphStyle('GDef', parent=styles['Normal'],
        fontSize=8.5, leading=11, textColor=GREY, leftIndent=10, spaceAfter=6)

    elements = []
    severity = get_severity_details(case_data.get("severity", 2))
    attack_type = case_data.get("attack_type", "Security Event")

    # ═══════════════════════════════════════════════════════
    #  COVER / HEADER
    # ═══════════════════════════════════════════════════════
    elements.append(Paragraph("SECURITY INCIDENT REPORT", title_style))
    elements.append(Paragraph(f"Report ID: {incident_id}", subtitle_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", subtitle_style))
    elements.append(Paragraph(
        f"Classification: <b>TLP:AMBER</b> — Limited distribution, recipients only", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
    elements.append(Spacer(1, 10))

    # ═══════════════════════════════════════════════════════
    #  SECTION 1: EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════
    elements.append(Paragraph("1. EXECUTIVE SUMMARY", heading_style))
    elements.append(Paragraph(
        f"<b>What happened:</b> A <font color='{severity['color'].hexval()}'><b>"
        f"{severity['label']}</b></font>-severity security incident of type "
        f"<b>{attack_type}</b> was detected on device <b>"
        f"{case_data.get('agent_name', 'Unknown')}</b> "
        f"(IP: {case_data.get('agent_ip', 'N/A')}).",
        body_style))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        f"<b>When:</b> The attack was first detected at <b>{case_data.get('timestamp', 'N/A')}"
        f"</b> and was resolved by <b>{case_data.get('resolution_time', 'N/A')}</b>, "
        f"giving a Mean Time To Respond (MTTR) of <b>{case_data.get('mttr', 'N/A')}</b>.",
        body_style))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        f"<b>Outcome:</b> The threat was <b>{case_data.get('status', 'detected')}</b>. "
        f"The AI-powered SOAR pipeline handled this incident automatically without requiring "
        f"manual intervention from a human analyst.",
        body_style))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        f"<i>Severity meaning: {severity['meaning']}</i>", note_style))
    elements.append(Spacer(1, 10))

    # ═══════════════════════════════════════════════════════
    #  SECTION 2: WHAT IS THIS ATTACK?
    # ═══════════════════════════════════════════════════════
    elements.append(Paragraph("2. WHAT IS THIS ATTACK?", heading_style))
    explanation = get_attack_explanation(attack_type)
    elements.append(Paragraph(explanation, body_style))
    elements.append(Spacer(1, 10))

    # ═══════════════════════════════════════════════════════
    #  SECTION 3: INCIDENT DETAILS
    # ═══════════════════════════════════════════════════════
    elements.append(Paragraph("3. INCIDENT DETAILS", heading_style))
    overview_data = [
        ["Field", "Value", "What This Means"],
        ["Incident Title", case_data.get("title", "N/A"), "Short name for this incident"],
        ["Severity Level", severity["label"],  severity["meaning"][:60]],
        ["Current Status", case_data.get("status", "Open"), "Whether the threat is still active"],
        ["Detection Time", case_data.get("timestamp", "N/A"), "When the system first noticed the attack"],
        ["Resolution Time", case_data.get("resolution_time", "N/A"), "When the attack was fully stopped"],
        ["MTTR", case_data.get("mttr", "N/A"), "Mean Time To Respond — how fast we reacted"],
        ["AI Triage Score", f"{case_data.get('triage_score', 'N/A')}%",
         "ML model confidence that this is a real threat (0-100%)"],
    ]
    t = _make_table(overview_data, [95, 165, 240], header=True)
    elements.append(t)
    elements.append(Spacer(1, 10))

    # ═══════════════════════════════════════════════════════
    #  SECTION 4: AFFECTED DEVICE
    # ═══════════════════════════════════════════════════════
    elements.append(Paragraph("4. AFFECTED DEVICE", heading_style))
    elements.append(Paragraph(
        "The following device was targeted. In cybersecurity, we call each monitored "
        "computer an <b>Agent</b> — software installed on it that sends security data to "
        "our central monitoring system (Wazuh).", body_style))
    elements.append(Spacer(1, 6))
    device_data = [
        ["Property", "Value", "What This Means"],
        ["Agent ID", case_data.get("agent_id", "001"), "Unique identifier in our monitoring system"],
        ["Hostname", case_data.get("agent_name", "Unknown"), "The computer's name on the network"],
        ["IP Address", case_data.get("agent_ip", "Unknown"),
         "The device's network address (like a postal address for computers)"],
        ["Operating System", case_data.get("agent_os", "Unknown"), "Software that runs the device"],
        ["Device Role", case_data.get("agent_role", "Endpoint"),
         "What this device is used for in the organization"],
    ]
    t = _make_table(device_data, [95, 165, 240], header=True)
    elements.append(t)
    elements.append(Spacer(1, 10))

    # ═══════════════════════════════════════════════════════
    #  SECTION 5: THREAT INTELLIGENCE
    # ═══════════════════════════════════════════════════════
    elements.append(Paragraph("5. THREAT INTELLIGENCE", heading_style))
    elements.append(Paragraph(
        "Our system automatically looked up the attacker's IP address in global "
        "<b>Threat Intelligence databases (MISP)</b> — shared registries of known "
        "attackers maintained by security organizations around the world. Here is what we found:",
        body_style))
    elements.append(Spacer(1, 6))
    threat_data = [
        ["Property", "Value", "What This Means"],
        ["Attack Type", case_data.get("attack_type", "N/A"), "The category of cyberattack"],
        ["MITRE ATT&CK ID", case_data.get("mitre_id", "N/A"),
         "Reference ID in the global attack knowledge base"],
        ["Wazuh Rule ID", case_data.get("rule_id", "N/A"),
         "The detection rule that caught this attack"],
        ["Rule Severity Level", str(case_data.get("rule_level", "N/A")),
         "Wazuh severity: 0 = noise, 15 = critical attack"],
    ]
    for match in case_data.get("misp_matches", []):
        threat_data.append([
            "MISP Match",
            f"{match.get('threat', '')}",
            f"Threat Intel score: {match.get('score', '')} — higher = more dangerous"
        ])
    t = _make_table(threat_data, [95, 165, 240], header=True)
    elements.append(t)
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        "<i><b>MITRE ATT&amp;CK</b> is a globally recognized encyclopedia of cyberattack "
        "techniques maintained by the MITRE Corporation. Each attack type has a unique ID "
        "(like T1110 for Brute Force) that helps security teams speak a common language.</i>",
        note_style))
    elements.append(Spacer(1, 10))

    # ═══════════════════════════════════════════════════════
    #  SECTION 6: INDICATORS OF COMPROMISE (IOCs)
    # ═══════════════════════════════════════════════════════
    observables = case_data.get("observables", [])
    if observables:
        elements.append(Paragraph("6. INDICATORS OF COMPROMISE (IOCs)", heading_style))
        elements.append(Paragraph(
            "<b>Indicators of Compromise (IOCs)</b> are digital clues left behind by an attacker — "
            "like fingerprints at a crime scene. They include IP addresses, file hashes "
            "(unique digital fingerprints of files), domain names, and email addresses. "
            "Security teams use IOCs to identify and block future attacks from the same source.",
            body_style))
        elements.append(Spacer(1, 6))
        obs_table_data = [["Type", "Value", "Tags", "Meaning"]]
        for obs in observables:
            obs_type = obs.get("type", "")
            obs_val = obs.get("value", "")
            tags = ", ".join(obs.get("tags", []))
            if "source" in tags.lower() or "malicious" in tags.lower():
                meaning = "Attacker's address — the origin of the attack"
            elif "destination" in tags.lower() or "internal" in tags.lower():
                meaning = "Our device that was targeted by the attacker"
            elif "hash" in obs_type:
                meaning = "Digital fingerprint of a suspicious file"
            else:
                meaning = "Relevant evidence from the incident"
            obs_table_data.append([obs_type.upper(), obs_val, tags, meaning])
        t = _make_table(obs_table_data, [45, 135, 140, 180], header=True)
        elements.append(t)
        elements.append(Spacer(1, 10))

    # ═══════════════════════════════════════════════════════
    #  SECTION 7: AUTOMATED RESPONSE TIMELINE
    # ═══════════════════════════════════════════════════════
    actions = case_data.get("actions_taken", [])
    if actions:
        elements.append(Paragraph("7. AUTOMATED RESPONSE TIMELINE", heading_style))
        elements.append(Paragraph(
            "The following steps were performed <b>automatically</b> by our SOAR "
            "(Security Orchestration, Automation, and Response) system — no human analyst "
            "was needed. Each step happened within seconds of detection:", body_style))
        elements.append(Spacer(1, 6))

        timeline_data = [["Step", "Time", "What Happened", "Why This Matters"]]
        explanations = [
            "System detected suspicious activity through continuous monitoring",
            "Alert was forwarded to our case management system for tracking",
            "Looked up the attacker in global threat intelligence databases",
            "AI model calculated the probability this is a real attack",
            "Firewall rule was applied to block the attacker's IP address",
            "Confirmed the threat is neutralized and the device is clean",
        ]
        for i, action in enumerate(actions):
            if isinstance(action, dict):
                time_str = action.get("time", "")
                desc = action.get("description", "")
            else:
                time_str = ""
                desc = str(action)
            why = explanations[i] if i < len(explanations) else "Part of the automated response chain"
            timeline_data.append([f"Step {i+1}", time_str, desc, why])

        t = _make_table(timeline_data, [40, 50, 225, 185], header=True)
        elements.append(t)
        elements.append(Spacer(1, 10))

    # ═══════════════════════════════════════════════════════
    #  SECTION 8: AI ANALYSIS & RECOMMENDATIONS
    # ═══════════════════════════════════════════════════════
    elements.append(PageBreak())
    elements.append(Paragraph("8. AI ANALYSIS, IMPACT & RECOMMENDATIONS", heading_style))
    elements.append(Paragraph(
        "The following analysis was generated by our AI system (powered by Machine Learning "
        "models and optionally the Google Gemini Large Language Model). It assesses the root "
        "cause, potential business impact, and provides actionable steps to prevent similar "
        "incidents in the future.", body_style))
    elements.append(Spacer(1, 8))

    ai_analysis = get_llm_analysis(case_data)
    for line in ai_analysis.split("\n"):
        line = line.strip()
        if not line:
            continue
        # Make section headers bold
        if line.isupper() or line.startswith("EXECUTIVE") or line.startswith("TECHNICAL") \
                or line.startswith("BUSINESS") or line.startswith("RECOMMEND"):
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(f"<b>{line}</b>", bold_body))
        elif line.startswith(("1.", "2.", "3.", "4.", "5.")):
            elements.append(Paragraph(f"&nbsp;&nbsp;{line}", body_style))
        elif line.startswith("- "):
            elements.append(Paragraph(f"&nbsp;&nbsp;&nbsp;• {line[2:]}", body_style))
        else:
            elements.append(Paragraph(line, body_style))
        elements.append(Spacer(1, 2))
    elements.append(Spacer(1, 10))

    # ═══════════════════════════════════════════════════════
    #  SECTION 9: AI CONFIDENCE DASHBOARD
    # ═══════════════════════════════════════════════════════
    elements.append(Paragraph("9. AI CONFIDENCE SCORES", heading_style))
    elements.append(Paragraph(
        "Our pipeline uses multiple AI/ML models to analyse each alert. Here are the scores "
        "from each model for this incident:", body_style))
    elements.append(Spacer(1, 6))
    score_data = [
        ["AI Model", "Score", "Decision", "Explanation"],
        ["ML Triage\n(XGBoost)",
         f"{case_data.get('triage_score', 'N/A')}%",
         "AUTO_BLOCK" if case_data.get('triage_score', 0) and
            (isinstance(case_data.get('triage_score'), (int,float)) and case_data.get('triage_score', 0) >= 90)
            else "REVIEW",
         "> 90% = auto-block, 50-89% = human review, < 50% = auto-close as noise"],
        ["Anomaly Detection\n(Isolation Forest)",
         case_data.get("anomaly_score", "N/A"),
         "ANOMALY" if case_data.get("is_anomaly") else "NORMAL",
         "Flags behavior that deviates from normal patterns learned over time"],
        ["Blast Radius\n(Graph Analysis)",
         f"{case_data.get('blast_radius_count', 'N/A')} hosts at risk",
         "CONTAINED" if case_data.get("status", "").lower().find("resolved") >= 0 else "MONITORING",
         "Predicts which neighbouring devices the attacker could reach next"],
    ]
    t = _make_table(score_data, [85, 65, 80, 270], header=True)
    elements.append(t)
    elements.append(Spacer(1, 10))

    # ═══════════════════════════════════════════════════════
    #  SECTION 10: GLOSSARY
    # ═══════════════════════════════════════════════════════
    elements.append(Paragraph("10. GLOSSARY OF TECHNICAL TERMS", heading_style))
    elements.append(Paragraph(
        "This section defines every technical term used in this report so that anyone — "
        "regardless of technical background — can fully understand the incident.",
        body_style))
    elements.append(Spacer(1, 6))

    glossary = [
        ("SOAR", "Security Orchestration, Automation, and Response — a system that automatically "
         "detects, analyses, and responds to cyber threats without human intervention."),
        ("SIEM", "Security Information and Event Management — collects and analyses security "
         "logs from across all devices. Wazuh is our SIEM."),
        ("Wazuh", "Open-source security monitoring platform that acts as our SIEM and EDR. "
         "It collects logs, detects threats, and can execute automated responses."),
        ("TheHive", "Open-source incident response platform used for case management — "
         "tracking, investigating, and closing security incidents."),
        ("Cortex", "Analysis and response engine linked to TheHive. Runs automated "
         "investigations (analyzers) and containment actions (responders)."),
        ("MISP", "Malware Information Sharing Platform — a global database of known threats, "
         "attacker IPs, malware fingerprints, and attack patterns shared between organizations."),
        ("MITRE ATT&CK", "A comprehensive knowledge base of adversary tactics and techniques "
         "based on real-world observations. Used worldwide as a standard reference."),
        ("IOC", "Indicator of Compromise — digital evidence (IP addresses, file hashes, "
         "domains) that indicates a security breach has occurred."),
        ("Brute Force", "An attack that systematically tries all possible passwords or keys "
         "until the correct one is found. Like trying every combination on a lock."),
        ("SSH", "Secure Shell — a protocol for securely accessing a computer's command "
         "line remotely. Often targeted because it provides full system control."),
        ("ML Triage", "Machine Learning Triage — our XGBoost AI model that scores each "
         "alert with a confidence percentage to decide if it needs human attention."),
        ("Isolation Forest", "An unsupervised ML algorithm that learns 'normal' behavior "
         "and flags anything that deviates significantly as an anomaly."),
        ("Blast Radius", "The set of devices and systems that could be affected if a "
         "compromised host is used as a launch point for further attacks."),
        ("MTTR", "Mean Time To Respond — the average time between detection and resolution "
         "of a security incident. Lower MTTR = better security posture."),
        ("TLP", "Traffic Light Protocol — a system for classifying the sensitivity of "
         "information. AMBER means limited sharing: recipients only."),
        ("Firewall Rule", "A network rule that allows or blocks specific traffic. A "
         "'firewall-drop' rule blocks all communication from a specific IP address."),
        ("Active Response", "An automated action taken by the security system in response "
         "to a detected threat, such as blocking an IP or killing a process."),
        ("EDR", "Endpoint Detection and Response — security software on individual devices "
         "that monitors for and responds to threats in real-time."),
    ]

    for term, definition in glossary:
        elements.append(Paragraph(f"<b>{term}</b>", glossary_term))
        elements.append(Paragraph(definition, glossary_def))

    # ═══════════════════════════════════════════════════════
    #  FOOTER
    # ═══════════════════════════════════════════════════════
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        f"This report was automatically generated by the <b>SOAR Incident Report Generator</b> "
        f"(Module 3.8). AI analysis powered by XGBoost, Isolation Forest, NetworkX, and "
        f"Google Gemini LLM. Report ID: {incident_id}. "
        f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}.",
        footer_style))
    elements.append(Paragraph(
        "CONFIDENTIAL — This document is classified TLP:AMBER. "
        "Do not distribute outside the authorized recipient list.",
        footer_style))

    # ── Build PDF ──
    doc.build(elements)
    return output_path


# ═══════════════════════════════════════════════════════
#  DEMO DATA (realistic incident)
# ═══════════════════════════════════════════════════════
DEMO_CASE = {
    "incident_id": "IR-2026-0047",
    "title": "SSH Brute Force Attack from APT28 Infrastructure",
    "severity": 4,
    "status": "Resolved (Automated)",
    "timestamp": "2026-03-06 12:00:01",
    "resolution_time": "2026-03-06 12:00:15",
    "mttr": "14 seconds",
    "agent_id": "001",
    "agent_name": "kali-vm-01",
    "agent_ip": "192.168.64.9",
    "agent_os": "Kali Linux 2025.1",
    "agent_role": "Security Testing Workstation",
    "attack_type": "SSH Brute Force (Credential Stuffing)",
    "mitre_id": "T1110 — Brute Force",
    "rule_id": "100001",
    "rule_level": 10,
    "triage_score": 97,
    "anomaly_score": "56.5",
    "is_anomaly": True,
    "blast_radius_count": 6,
    "misp_matches": [
        {"threat": "APT28 / Fancy Bear C2 Server", "score": "100/100"},
        {"threat": "Known SSH Scanner (Shodan)", "score": "85/100"},
    ],
    "observables": [
        {"type": "ip", "value": "91.219.236.222", "tags": ["source", "malicious", "APT28"]},
        {"type": "ip", "value": "192.168.64.9", "tags": ["destination", "internal"]},
    ],
    "actions_taken": [
        {"time": "12:00:01", "description": "Wazuh detected 50 failed SSH logins from 91.219.236.222"},
        {"time": "12:00:02", "description": "Alert forwarded to TheHive — Case #4871 created"},
        {"time": "12:00:03", "description": "Cortex queried MISP — IP matched APT28 infrastructure"},
        {"time": "12:00:05", "description": "ML Triage Analyzer scored alert at 97% — AUTO_BLOCK"},
        {"time": "12:00:06", "description": "Wazuh Active Response: firewall-drop 91.219.236.222"},
        {"time": "12:00:14", "description": "Threat neutralized. Agent confirmed clean. Case resolved."},
    ],
}


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        path = generate_pdf_report(DEMO_CASE)
        print(f"[+] Demo report generated: {path}")
    elif len(sys.argv) > 1 and sys.argv[1] == "--case":
        case_json = sys.argv[2]
        case_data = json.loads(case_json)
        path = generate_pdf_report(case_data)
        print(f"[+] Report generated: {path}")
    else:
        print("Usage:")
        print("  python report_generator.py --demo     # Generate demo PDF")
        print("  python report_generator.py --case '{}'  # Generate from case JSON")
