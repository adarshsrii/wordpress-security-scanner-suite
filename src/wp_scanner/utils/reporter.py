"""
Report generation utilities for multiple output formats.
Comprehensive PDF reports with all scanner results.
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, ListFlowable, ListItem
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


class ReportGenerator:
    """Generate security reports in multiple formats."""

    def __init__(self, results: Dict[str, Any], output_dir: str = "output"):
        self.results = results
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.target = results.get('target', 'Unknown')
        self.domain = self._extract_domain(self.target)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    def _extract_domain(self, url: str) -> str:
        """Extract domain name for folder naming (preserves dots, only replaces colons for ports)."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        # Only replace colon (for ports like :8080), keep dots for readability
        return parsed.netloc.replace(':', '_')

    def _get_filepath(self, extension: str, prefix: str = "report") -> Path:
        filename = f"{prefix}.{extension}"
        return self.output_dir / self.domain / filename

    def _ensure_target_dir(self):
        target_dir = self.output_dir / self.domain
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    def calculate_grade(self, score: int) -> str:
        if score >= 90: return 'A+'
        elif score >= 85: return 'A'
        elif score >= 80: return 'B+'
        elif score >= 75: return 'B'
        elif score >= 70: return 'C+'
        elif score >= 65: return 'C'
        elif score >= 60: return 'D+'
        elif score >= 55: return 'D'
        else: return 'F'

    def to_json(self, pretty: bool = True) -> Path:
        self._ensure_target_dir()
        filepath = self._get_filepath('json', 'full_scan')
        with open(filepath, 'w') as f:
            if pretty:
                json.dump(self.results, f, indent=2, default=str)
            else:
                json.dump(self.results, f, default=str)
        return filepath

    def to_markdown(self) -> Path:
        self._ensure_target_dir()
        filepath = self._get_filepath('md', 'security_report')
        score = self.results.get('risk_score', 0)
        grade = self.calculate_grade(score)
        vulns = self.results.get('vulnerabilities', {})

        md = f"""# WordPress Security Assessment Report

**Target:** {self.target}
**Scan Time:** {self.results.get('scan_time', 'N/A')}
**Scan Mode:** {self.results.get('scan_mode', 'N/A').upper()}
**WordPress Version:** {self.results.get('wordpress_version', 'Unknown')}

---

## Security Score: {score}/100 (Grade: {grade})

---

## Vulnerability Summary

| Severity | Count |
|----------|-------|
| Critical | {len(vulns.get('critical', []))} |
| High | {len(vulns.get('high', []))} |
| Medium | {len(vulns.get('medium', []))} |
| Low | {len(vulns.get('low', []))} |
| **Total** | **{sum(len(v) for v in vulns.values())}** |

---

"""
        # Backdoors
        backdoors = self.results.get('backdoors', {}).get('found', [])
        if backdoors:
            md += """## !!! SITE COMPROMISED - BACKDOORS DETECTED !!!

| Path | Type | Signatures |
|------|------|------------|
"""
            for bd in backdoors:
                sigs = ', '.join(bd.get('signatures', [])[:3])
                md += f"| `{bd['path']}` | {bd.get('type', 'unknown')} | {sigs} |\n"
            md += "\n---\n\n"

        # All vulnerabilities
        for severity in ['critical', 'high', 'medium', 'low']:
            if vulns.get(severity):
                md += f"## {severity.upper()} Vulnerabilities\n\n"
                for i, vuln in enumerate(vulns[severity], 1):
                    md += f"### {i}. {vuln['title']}\n"
                    if vuln.get('cve'):
                        md += f"**CVE:** {vuln.get('cve')} | **CVSS:** {vuln.get('cvss', 'N/A')}\n\n"
                    md += f"**Description:** {vuln['description']}\n\n"
                    md += f"**Remediation:** {vuln['remediation']}\n\n"
                    if vuln.get('evidence'):
                        md += f"**Evidence:** {vuln['evidence']}\n\n"
                    md += "---\n\n"

        # Exposed files
        exposed_files = self.results.get('exposed_files', [])
        if exposed_files:
            md += f"## Exposed Sensitive Files ({len(exposed_files)})\n\n"
            md += "| Path | Severity | Size |\n|------|----------|------|\n"
            for f in exposed_files[:30]:
                md += f"| `{f['path']}` | {f['severity']} | {f['size']} bytes |\n"
            md += "\n"

        # Plugins
        plugins = self.results.get('plugins', {})
        if plugins:
            md += f"## Detected Plugins ({len(plugins)})\n\n"
            for plugin, data in list(plugins.items())[:20]:
                md += f"- **{plugin}** (v{data.get('version', 'unknown')})\n"
            md += "\n"

        md += f"\n---\n*Generated by WordPress Security Scanner Suite v2.0*\n"

        with open(filepath, 'w') as f:
            f.write(md)
        return filepath

    def to_csv(self) -> Path:
        self._ensure_target_dir()
        filepath = self._get_filepath('csv', 'vulnerabilities')
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Severity', 'Title', 'Description', 'CVE', 'CVSS', 'Remediation', 'Evidence'])
            for severity in ['critical', 'high', 'medium', 'low']:
                for vuln in self.results.get('vulnerabilities', {}).get(severity, []):
                    writer.writerow([
                        severity.upper(),
                        vuln.get('title', ''),
                        vuln.get('description', '')[:500],
                        vuln.get('cve', ''),
                        vuln.get('cvss', ''),
                        vuln.get('remediation', '')[:500],
                        vuln.get('evidence', '')[:200],
                    ])
        return filepath

    def to_summary(self) -> Path:
        self._ensure_target_dir()
        filepath = self._get_filepath('txt', 'summary')
        score = self.results.get('risk_score', 0)
        grade = self.calculate_grade(score)
        vulns = self.results.get('vulnerabilities', {})

        summary = f"""WordPress Security Scan Summary
{'=' * 50}
Target: {self.target}
Scan Time: {self.results.get('scan_time', 'N/A')}
WordPress Version: {self.results.get('wordpress_version', 'Unknown')}

SECURITY SCORE: {score}/100 (Grade: {grade})

VULNERABILITIES:
  Critical: {len(vulns.get('critical', []))}
  High:     {len(vulns.get('high', []))}
  Medium:   {len(vulns.get('medium', []))}
  Low:      {len(vulns.get('low', []))}

FINDINGS:
  Exposed Files: {len(self.results.get('exposed_files', []))}
  Plugins Found: {len(self.results.get('plugins', {}))}
  Themes Found:  {len(self.results.get('themes', {}))}
  Users Found:   {len(self.results.get('users', []))}
  Backdoors:     {len(self.results.get('backdoors', {}).get('found', []))}

{'=' * 50}
"""
        with open(filepath, 'w') as f:
            f.write(summary)
        return filepath

    def _create_styles(self):
        """Create all PDF styles."""
        styles = getSampleStyleSheet()

        # Title style
        styles.add(ParagraphStyle(
            name='ReportTitle', parent=styles['Heading1'],
            fontSize=22, spaceAfter=15, alignment=TA_CENTER,
            textColor=colors.HexColor('#1a1a2e')
        ))

        # Section headers
        styles.add(ParagraphStyle(
            name='SectionHeader', parent=styles['Heading2'],
            fontSize=13, spaceBefore=12, spaceAfter=6,
            textColor=colors.white, backColor=colors.HexColor('#16213e'),
            borderPadding=5, leftIndent=0
        ))

        # Subsection headers
        styles.add(ParagraphStyle(
            name='SubHeader', parent=styles['Heading3'],
            fontSize=11, spaceBefore=8, spaceAfter=4,
            textColor=colors.HexColor('#0f3460'), fontName='Helvetica-Bold'
        ))

        # Body text
        styles.add(ParagraphStyle(
            name='ReportBody', parent=styles['Normal'],
            fontSize=9, spaceAfter=4, leading=11
        ))

        # Small text
        styles.add(ParagraphStyle(
            name='SmallText', parent=styles['Normal'],
            fontSize=8, spaceAfter=2, leading=10, textColor=colors.HexColor('#444444')
        ))

        # Code/evidence text
        styles.add(ParagraphStyle(
            name='CodeText', parent=styles['Normal'],
            fontSize=7, fontName='Courier', backColor=colors.HexColor('#f5f5f5'),
            borderPadding=3, spaceAfter=4
        ))

        # Alert styles
        styles.add(ParagraphStyle(
            name='AlertCritical', parent=styles['Normal'],
            fontSize=10, textColor=colors.white, backColor=colors.HexColor('#dc3545'),
            borderPadding=8, alignment=TA_CENTER, fontName='Helvetica-Bold'
        ))

        styles.add(ParagraphStyle(
            name='AlertWarning', parent=styles['Normal'],
            fontSize=9, textColor=colors.HexColor('#856404'),
            backColor=colors.HexColor('#fff3cd'), borderPadding=5
        ))

        # Score styles
        styles.add(ParagraphStyle(
            name='ScoreGood', parent=styles['Normal'],
            fontSize=28, alignment=TA_CENTER, textColor=colors.HexColor('#28a745'),
            fontName='Helvetica-Bold'
        ))

        styles.add(ParagraphStyle(
            name='ScoreBad', parent=styles['Normal'],
            fontSize=28, alignment=TA_CENTER, textColor=colors.HexColor('#dc3545'),
            fontName='Helvetica-Bold'
        ))

        return styles

    def _create_table(self, data, col_widths, header_color='#16213e'):
        """Create a styled table."""
        table = Table(data, colWidths=col_widths)
        style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(header_color)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]
        table.setStyle(TableStyle(style))
        return table

    def to_pdf(self) -> Path:
        """Generate comprehensive PDF security report with ALL scanner results."""
        self._ensure_target_dir()
        filepath = self._get_filepath('pdf', 'security_report')

        doc = SimpleDocTemplate(
            str(filepath), pagesize=letter,
            rightMargin=0.5*inch, leftMargin=0.5*inch,
            topMargin=0.5*inch, bottomMargin=0.5*inch
        )

        styles = self._create_styles()
        story = []

        score = self.results.get('risk_score', 0)
        grade = self.calculate_grade(score)
        vulns = self.results.get('vulnerabilities', {})
        attack_surface = self.results.get('attack_surface', {})

        # ========== PAGE 1: EXECUTIVE SUMMARY ==========
        story.append(Paragraph("WordPress Security Assessment Report", styles['ReportTitle']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0f3460')))
        story.append(Spacer(1, 0.1*inch))

        # Target info
        server_info = self.results.get('server_info', {})
        info_data = [
            ['Property', 'Value', 'Property', 'Value'],
            ['Target URL', self.target[:40], 'Scan Date', self.results.get('scan_time', 'N/A')[:20]],
            ['Scan Mode', self.results.get('scan_mode', 'N/A').upper(), 'WP Version', self.results.get('wordpress_version', 'Unknown')],
            ['Web Server', server_info.get('server', 'Unknown')[:25], 'Powered By', server_info.get('x_powered_by', 'Unknown')[:25]],
        ]
        story.append(self._create_table(info_data, [1.1*inch, 2.3*inch, 1.1*inch, 2.3*inch]))
        story.append(Spacer(1, 0.15*inch))

        # Score
        score_style = styles['ScoreGood'] if score >= 70 else styles['ScoreBad']
        story.append(Paragraph(f"Security Score: {score}/100 (Grade: {grade})", score_style))
        story.append(Spacer(1, 0.1*inch))

        # BACKDOOR ALERT
        backdoors = self.results.get('backdoors', {}).get('found', [])
        if backdoors:
            story.append(Paragraph("!!! CRITICAL: BACKDOORS DETECTED - SITE COMPROMISED !!!", styles['AlertCritical']))
            story.append(Spacer(1, 0.05*inch))

        # Vulnerability summary table
        story.append(Paragraph("Vulnerability Summary", styles['SectionHeader']))
        vuln_data = [
            ['Severity', 'Count', 'Status'],
            ['CRITICAL', str(len(vulns.get('critical', []))), 'IMMEDIATE ACTION' if vulns.get('critical') else 'OK'],
            ['HIGH', str(len(vulns.get('high', []))), 'ACTION REQUIRED' if vulns.get('high') else 'OK'],
            ['MEDIUM', str(len(vulns.get('medium', []))), 'REVIEW' if vulns.get('medium') else 'OK'],
            ['LOW', str(len(vulns.get('low', []))), 'MONITOR' if vulns.get('low') else 'OK'],
            ['TOTAL', str(sum(len(v) for v in vulns.values())), ''],
        ]
        vuln_table = Table(vuln_data, colWidths=[1.5*inch, 1*inch, 2*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8d7da')),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#fff3cd')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#d1ecf1')),
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#d4edda')),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#e2e3e5')),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(vuln_table)
        story.append(Spacer(1, 0.1*inch))

        # Quick stats
        story.append(Paragraph("Scan Statistics", styles['SectionHeader']))
        stats_data = [
            ['Metric', 'Value', 'Metric', 'Value'],
            ['Plugins Found', str(len(self.results.get('plugins', {}))), 'Themes Found', str(len(self.results.get('themes', {})))],
            ['Users Enumerated', str(len(self.results.get('users', []))), 'Exposed Files', str(len(self.results.get('exposed_files', [])))],
            ['Missing Headers', str(len(self.results.get('security_headers', {}).get('missing', []))), 'Backdoors', str(len(backdoors))],
        ]
        story.append(self._create_table(stats_data, [1.4*inch, 1.2*inch, 1.4*inch, 1.2*inch]))

        # ========== PAGE 2: BACKDOORS & CRITICAL ==========
        story.append(PageBreak())

        # Backdoor Detection Section
        story.append(Paragraph("1. BACKDOOR DETECTION (Domain Scanner)", styles['SectionHeader']))
        if backdoors:
            story.append(Paragraph("MALICIOUS FILES DETECTED:", styles['AlertWarning']))
            bd_data = [['File Path', 'Type', 'Signatures Matched']]
            for bd in backdoors[:20]:
                sigs = ', '.join(bd.get('signatures', [])[:3])
                bd_data.append([bd.get('path', '')[:40], bd.get('type', 'shell'), sigs[:35]])
            story.append(self._create_table(bd_data, [2.5*inch, 1*inch, 3*inch], '#dc3545'))
        else:
            story.append(Paragraph("No backdoors or web shells detected.", styles['ReportBody']))
        story.append(Spacer(1, 0.08*inch))

        # Suspicious files
        suspicious = self.results.get('backdoors', {}).get('suspicious', [])
        if suspicious:
            story.append(Paragraph(f"Suspicious Files ({len(suspicious)}):", styles['SubHeader']))
            for sf in suspicious[:10]:
                story.append(Paragraph(f"- {sf.get('path', '')} ({sf.get('size', 0)} bytes)", styles['SmallText']))

        # Malicious content
        malicious = attack_surface.get('malicious_content', {})
        if malicious.get('crypto_miners'):
            story.append(Paragraph("Crypto Miners Detected:", styles['SubHeader']))
            for miner in malicious['crypto_miners']:
                story.append(Paragraph(f"- {miner}", styles['ReportBody']))
        if malicious.get('suspicious_scripts'):
            story.append(Paragraph("Suspicious Scripts:", styles['SubHeader']))
            for script in malicious['suspicious_scripts'][:5]:
                story.append(Paragraph(f"- {script[:70]}...", styles['SmallText']))

        story.append(Spacer(1, 0.1*inch))

        # Critical Vulnerabilities
        if vulns.get('critical'):
            story.append(Paragraph(f"CRITICAL VULNERABILITIES ({len(vulns['critical'])})", styles['SectionHeader']))
            for i, vuln in enumerate(vulns['critical'], 1):
                story.append(Paragraph(f"{i}. {vuln['title']}", styles['SubHeader']))
                if vuln.get('cve'):
                    story.append(Paragraph(f"CVE: {vuln.get('cve')} | CVSS: {vuln.get('cvss', 'N/A')}", styles['SmallText']))
                story.append(Paragraph(f"Issue: {vuln['description']}", styles['ReportBody']))
                story.append(Paragraph(f"Fix: {vuln['remediation']}", styles['ReportBody']))
                if vuln.get('evidence'):
                    story.append(Paragraph(f"Evidence: {vuln['evidence'][:120]}", styles['CodeText']))
                story.append(Spacer(1, 0.05*inch))

        # ========== PAGE 3: HIGH & MEDIUM VULNS ==========
        story.append(PageBreak())

        if vulns.get('high'):
            story.append(Paragraph(f"HIGH SEVERITY VULNERABILITIES ({len(vulns['high'])})", styles['SectionHeader']))
            for i, vuln in enumerate(vulns['high'], 1):
                story.append(Paragraph(f"{i}. {vuln['title']}", styles['SubHeader']))
                story.append(Paragraph(vuln['description'], styles['ReportBody']))
                story.append(Paragraph(f"Remediation: {vuln['remediation']}", styles['SmallText']))
                story.append(Spacer(1, 0.04*inch))

        if vulns.get('medium'):
            story.append(Paragraph(f"MEDIUM SEVERITY FINDINGS ({len(vulns['medium'])})", styles['SectionHeader']))
            for i, vuln in enumerate(vulns['medium'], 1):
                story.append(Paragraph(f"{i}. {vuln['title']}: {vuln['description'][:180]}", styles['ReportBody']))

        if vulns.get('low'):
            story.append(Paragraph(f"LOW SEVERITY FINDINGS ({len(vulns['low'])})", styles['SectionHeader']))
            for i, vuln in enumerate(vulns['low'], 1):
                story.append(Paragraph(f"{i}. {vuln['title']}", styles['SmallText']))

        # ========== PAGE 4: REST API & XML-RPC ==========
        story.append(PageBreak())

        # REST API Scanner Results
        rest_api = attack_surface.get('rest_api', {})
        story.append(Paragraph("2. REST API SCANNER", styles['SectionHeader']))
        story.append(Paragraph(f"Accessible: {'Yes' if rest_api.get('accessible') else 'No'}", styles['ReportBody']))

        if rest_api.get('namespaces'):
            story.append(Paragraph(f"Exposed Namespaces ({len(rest_api['namespaces'])}):", styles['SubHeader']))
            ns_text = ', '.join(rest_api['namespaces'][:15])
            story.append(Paragraph(ns_text, styles['SmallText']))

        if rest_api.get('users_enumerated'):
            story.append(Paragraph(f"Users Enumerated ({len(rest_api['users_enumerated'])}):", styles['SubHeader']))
            user_data = [['ID', 'Username', 'Display Name', 'Profile URL']]
            for user in rest_api['users_enumerated'][:10]:
                user_data.append([
                    str(user.get('id', '')),
                    user.get('username', '')[:20],
                    user.get('name', '')[:20],
                    user.get('link', '')[:35]
                ])
            story.append(self._create_table(user_data, [0.5*inch, 1.3*inch, 1.5*inch, 2.5*inch]))

        if rest_api.get('endpoints_exposed'):
            story.append(Paragraph(f"Exposed Endpoints: {len(rest_api['endpoints_exposed'])}", styles['ReportBody']))
        story.append(Spacer(1, 0.1*inch))

        # XML-RPC Scanner Results
        xmlrpc = attack_surface.get('xmlrpc', {})
        story.append(Paragraph("3. XML-RPC SCANNER", styles['SectionHeader']))
        story.append(Paragraph(f"Accessible: {'Yes' if xmlrpc.get('accessible') else 'No'}", styles['ReportBody']))
        story.append(Paragraph(f"system.multicall Enabled: {'YES - CRITICAL' if xmlrpc.get('multicall_enabled') else 'No'}", styles['ReportBody']))
        story.append(Paragraph(f"pingback.ping Enabled: {'YES - SSRF Risk' if xmlrpc.get('pingback_enabled') else 'No'}", styles['ReportBody']))
        story.append(Paragraph(f"Brute Force Possible: {'Yes' if xmlrpc.get('brute_force_possible') else 'No'}", styles['ReportBody']))

        if xmlrpc.get('methods_available'):
            story.append(Paragraph(f"Available Methods ({len(xmlrpc['methods_available'])}):", styles['SubHeader']))
            methods_text = ', '.join(xmlrpc['methods_available'][:20])
            story.append(Paragraph(methods_text, styles['SmallText']))

        # ========== PAGE 5: AUTH & INJECTION ==========
        story.append(PageBreak())

        # Authentication Scanner
        story.append(Paragraph("4. AUTHENTICATION SCANNER", styles['SectionHeader']))
        users = self.results.get('users', [])
        if users:
            story.append(Paragraph(f"Enumerated Users ({len(users)}):", styles['SubHeader']))
            auth_data = [['ID', 'Username', 'Method', 'URL/Name']]
            for user in users[:15]:
                auth_data.append([
                    str(user.get('id', 'N/A')),
                    user.get('username', user.get('name', 'Unknown'))[:20],
                    user.get('method', 'unknown'),
                    user.get('url', user.get('link', ''))[:40]
                ])
            story.append(self._create_table(auth_data, [0.5*inch, 1.5*inch, 1.2*inch, 3*inch]))
        else:
            story.append(Paragraph("No users enumerated.", styles['ReportBody']))

        # Login security (if available)
        # This would come from auth scanner results
        story.append(Spacer(1, 0.1*inch))

        # Injection Scanner (if aggressive mode)
        injection = attack_surface.get('injection', {})
        story.append(Paragraph("5. INJECTION SCANNER", styles['SectionHeader']))
        if injection:
            story.append(Paragraph(f"SQL Injection Tests: {len(injection.get('sql_tests', []))}", styles['ReportBody']))
            story.append(Paragraph(f"XSS Tests: {len(injection.get('xss_tests', []))}", styles['ReportBody']))
            if injection.get('vulnerable_params'):
                story.append(Paragraph("Vulnerable Parameters Found:", styles['SubHeader']))
                for param in injection.get('vulnerable_params', [])[:10]:
                    story.append(Paragraph(f"- {param}", styles['SmallText']))
        else:
            story.append(Paragraph("Injection tests not performed (passive mode) or no vulnerabilities found.", styles['ReportBody']))

        # ========== PAGE 6: BACKUP & HEADERS ==========
        story.append(PageBreak())

        # Backup/Exposed Files Scanner
        exposed_files = self.results.get('exposed_files', [])
        story.append(Paragraph(f"6. BACKUP FILE SCANNER ({len(exposed_files)} files found)", styles['SectionHeader']))
        if exposed_files:
            file_data = [['Path', 'Severity', 'Size']]
            for f in exposed_files[:30]:
                file_data.append([f['path'][:50], f['severity'], f"{f['size']} bytes"])
            story.append(self._create_table(file_data, [3.5*inch, 1*inch, 1.2*inch]))
        else:
            story.append(Paragraph("No exposed backup or sensitive files found.", styles['ReportBody']))
        story.append(Spacer(1, 0.1*inch))

        # Security Headers Scanner
        headers = self.results.get('security_headers', {})
        story.append(Paragraph("7. SECURITY HEADERS SCANNER", styles['SectionHeader']))

        if headers.get('present'):
            story.append(Paragraph(f"Present Headers ({len(headers['present'])}):", styles['SubHeader']))
            for header, value in list(headers['present'].items())[:10]:
                story.append(Paragraph(f"<b>{header}:</b> {str(value)[:60]}", styles['SmallText']))

        if headers.get('missing'):
            story.append(Paragraph(f"Missing Headers ({len(headers['missing'])}):", styles['SubHeader']))
            missing_data = [['Header', 'Severity', 'Description', 'Recommended Value']]
            for h in headers['missing'][:12]:
                recommended = ', '.join(h.get('recommended', [])[:2]) if h.get('recommended') else 'See docs'
                missing_data.append([
                    h['header'][:22],
                    h['severity'],
                    h['description'][:35],
                    recommended[:25]
                ])
            story.append(self._create_table(missing_data, [1.5*inch, 0.8*inch, 2.2*inch, 1.8*inch]))

        # ========== PAGE 7: NETWORK & DNS ==========
        story.append(PageBreak())

        network = attack_surface.get('network', {})
        story.append(Paragraph("8. NETWORK SCANNER", styles['SectionHeader']))

        # DNS Records
        dns_records = network.get('dns_records', {})
        if dns_records:
            story.append(Paragraph("DNS Records:", styles['SubHeader']))
            dns_items = []
            if dns_records.get('a'):
                dns_items.append(f"A: {', '.join(dns_records['a'][:5])}")
            if dns_records.get('aaaa'):
                dns_items.append(f"AAAA: {', '.join(dns_records['aaaa'][:3])}")
            if dns_records.get('mx'):
                dns_items.append(f"MX: {', '.join(dns_records['mx'][:3])}")
            if dns_records.get('ns'):
                dns_items.append(f"NS: {', '.join(dns_records['ns'][:4])}")
            if dns_records.get('cname'):
                dns_items.append(f"CNAME: {dns_records['cname']}")
            if dns_records.get('soa'):
                dns_items.append(f"SOA: {dns_records['soa']}")
            if dns_records.get('txt'):
                for txt in dns_records['txt'][:3]:
                    dns_items.append(f"TXT: {txt[:70]}...")

            for item in dns_items:
                story.append(Paragraph(item, styles['SmallText']))
            story.append(Spacer(1, 0.08*inch))

        # SPF/DMARC
        spf_dmarc = network.get('spf_dmarc', {})
        if spf_dmarc:
            story.append(Paragraph("Email Security (SPF/DMARC):", styles['SubHeader']))
            story.append(Paragraph(f"SPF: {'Configured' if spf_dmarc.get('spf_valid') else 'NOT CONFIGURED'}", styles['ReportBody']))
            story.append(Paragraph(f"DMARC: {'Configured' if spf_dmarc.get('dmarc_valid') else 'NOT CONFIGURED'}", styles['ReportBody']))

        # DNSSEC & CAA
        dnssec = network.get('dnssec', {})
        caa = network.get('caa_records', {})
        story.append(Paragraph(f"DNSSEC: {'Enabled' if dnssec.get('enabled') else 'NOT ENABLED'}", styles['ReportBody']))
        story.append(Paragraph(f"CAA Records: {'Configured' if caa.get('has_caa') else 'NOT CONFIGURED'}", styles['ReportBody']))
        if caa.get('issuers'):
            story.append(Paragraph(f"Allowed CAs: {', '.join(caa['issuers'])}", styles['SmallText']))
        story.append(Spacer(1, 0.08*inch))

        # Open Ports
        open_ports = network.get('open_ports', {})
        if open_ports.get('open'):
            story.append(Paragraph(f"Open Ports ({len(open_ports['open'])}):", styles['SubHeader']))
            port_data = [['Port', 'Service', 'Severity', 'Description']]
            for p in open_ports['open'][:12]:
                port_data.append([str(p['port']), p['service'], p['severity'], p['description'][:30]])
            story.append(self._create_table(port_data, [0.6*inch, 1*inch, 0.8*inch, 3*inch]))

        # Reverse DNS
        reverse_dns = network.get('reverse_dns', {})
        if reverse_dns.get('ptr'):
            story.append(Paragraph(f"Reverse DNS: {reverse_dns['ptr']}", styles['SmallText']))

        # ========== PAGE 8: DOMAIN SECURITY ==========
        story.append(PageBreak())

        domain_security = self.results.get('domain_security', {})
        story.append(Paragraph("9. DOMAIN SCANNER", styles['SectionHeader']))

        # SSL/TLS
        ssl_info = domain_security.get('ssl', {})
        if ssl_info:
            story.append(Paragraph("SSL/TLS Certificate:", styles['SubHeader']))
            cert_info = ssl_info.get('cert_info', {})
            ssl_data = [
                ['Property', 'Value'],
                ['Valid', 'Yes' if ssl_info.get('valid') else 'No'],
                ['TLS Version', str(cert_info.get('tls_version', 'Unknown'))],
                ['Issuer', str(cert_info.get('issuer', {}))[:50]],
                ['Subject', str(cert_info.get('subject', {}))[:50]],
                ['Not Before', str(cert_info.get('not_before', 'Unknown'))],
                ['Not After', str(cert_info.get('not_after', 'Unknown'))],
                ['Days Until Expiry', str(cert_info.get('days_until_expiry', 'Unknown'))],
            ]
            story.append(self._create_table(ssl_data, [1.5*inch, 4.5*inch]))

            if ssl_info.get('issues'):
                story.append(Paragraph("SSL Issues:", styles['SubHeader']))
                for issue in ssl_info['issues']:
                    story.append(Paragraph(f"- {issue}", styles['SmallText']))

        # Server Disclosure
        server_disclosure = domain_security.get('server_disclosure', {})
        if server_disclosure:
            story.append(Paragraph("Server Information Disclosure:", styles['SubHeader']))
            story.append(Paragraph(f"Server: {server_disclosure.get('server', 'Unknown')}", styles['ReportBody']))
            story.append(Paragraph(f"X-Powered-By: {server_disclosure.get('powered_by', 'Not disclosed')}", styles['ReportBody']))
            if server_disclosure.get('php_version'):
                story.append(Paragraph(f"PHP Version: {server_disclosure['php_version']}", styles['ReportBody']))

        # Hidden Paths
        hidden_paths = domain_security.get('hidden_paths', {})
        if hidden_paths.get('found'):
            story.append(Paragraph(f"Hidden/Admin Paths Found ({len(hidden_paths['found'])}):", styles['SubHeader']))
            for path in hidden_paths['found'][:10]:
                status = 'ACCESSIBLE' if path.get('accessible') else 'Protected'
                story.append(Paragraph(f"- {path['path']} [{status}]", styles['SmallText']))

        # ========== PAGE 9: ADVANCED CHECKS ==========
        story.append(PageBreak())

        advanced = attack_surface.get('advanced', {})
        story.append(Paragraph("10. ADVANCED SCANNER", styles['SectionHeader']))

        # CORS
        cors = advanced.get('cors', {})
        story.append(Paragraph("CORS Policy:", styles['SubHeader']))
        story.append(Paragraph(f"Vulnerable: {'Yes' if cors.get('vulnerable') else 'No'}", styles['ReportBody']))
        if cors.get('issues'):
            for issue in cors['issues'][:5]:
                story.append(Paragraph(f"- {issue.get('endpoint', '')}: {issue.get('issue', '')}", styles['SmallText']))

        # Open Redirect
        redirect = advanced.get('open_redirect', {})
        story.append(Paragraph("Open Redirect:", styles['SubHeader']))
        story.append(Paragraph(f"Vulnerable: {'Yes' if redirect.get('vulnerable') else 'No'}", styles['ReportBody']))
        if redirect.get('endpoints'):
            for ep in redirect['endpoints'][:5]:
                story.append(Paragraph(f"- {ep.get('path', '')} via {ep.get('parameter', '')}", styles['SmallText']))

        # Clickjacking
        clickjack = advanced.get('clickjacking', {})
        story.append(Paragraph("Clickjacking Protection:", styles['SubHeader']))
        story.append(Paragraph(f"Protected: {'Yes' if clickjack.get('protected') else 'No'}", styles['ReportBody']))
        story.append(Paragraph(f"X-Frame-Options: {clickjack.get('x_frame_options', 'Not set')}", styles['SmallText']))

        # Debug Mode
        debug = advanced.get('debug_mode', {})
        story.append(Paragraph("Debug Mode:", styles['SubHeader']))
        story.append(Paragraph(f"Detected: {'YES - RISK' if debug.get('debug_detected') else 'No'}", styles['ReportBody']))
        if debug.get('indicators'):
            for ind in debug['indicators'][:5]:
                story.append(Paragraph(f"- {ind.get('indicator', '')}", styles['SmallText']))

        # TimThumb
        timthumb = advanced.get('timthumb', {})
        story.append(Paragraph("TimThumb Vulnerability:", styles['SubHeader']))
        story.append(Paragraph(f"Found: {'YES - CRITICAL' if timthumb.get('found') else 'No'}", styles['ReportBody']))

        # RevSlider
        revslider = advanced.get('revslider', {})
        story.append(Paragraph("RevSlider:", styles['SubHeader']))
        story.append(Paragraph(f"Found: {'Yes' if revslider.get('found') else 'No'} | Vulnerable: {'YES' if revslider.get('vulnerable') else 'No'}", styles['ReportBody']))

        # Rate Limiting
        rate_limit = advanced.get('api_rate_limiting', {})
        story.append(Paragraph("API Rate Limiting:", styles['SubHeader']))
        story.append(Paragraph(f"Protected: {'Yes' if rate_limit.get('rate_limited') else 'No'}", styles['ReportBody']))
        if rate_limit.get('vulnerable_endpoints'):
            story.append(Paragraph(f"Unprotected: {', '.join(rate_limit['vulnerable_endpoints'][:3])}", styles['SmallText']))

        # SSRF Pingback
        ssrf = advanced.get('ssrf_pingback', {})
        story.append(Paragraph("SSRF via Pingback:", styles['SubHeader']))
        story.append(Paragraph(f"Potential: {'Yes' if ssrf.get('ssrf_potential') else 'No'}", styles['ReportBody']))

        # Database Prefix
        db_prefix = advanced.get('database_prefix', {})
        story.append(Paragraph("Database Prefix:", styles['SubHeader']))
        story.append(Paragraph(f"Default (wp_): {'Yes' if db_prefix.get('default_prefix') else 'No/Hidden'}", styles['ReportBody']))

        # ========== PAGE 10: PLUGINS & RECOMMENDATIONS ==========
        story.append(PageBreak())

        # Plugin Scanner
        plugins = self.results.get('plugins', {})
        story.append(Paragraph(f"11. PLUGIN SCANNER ({len(plugins)} plugins found)", styles['SectionHeader']))
        if plugins:
            plugin_data = [['Plugin Name', 'Version', 'Detection Method']]
            for plugin, data in list(plugins.items())[:25]:
                plugin_data.append([plugin[:35], str(data.get('version', 'unknown')), data.get('detected_via', 'scan')])
            story.append(self._create_table(plugin_data, [3*inch, 1.2*inch, 1.5*inch]))
        else:
            story.append(Paragraph("No plugins detected.", styles['ReportBody']))

        # Themes
        themes = self.results.get('themes', {})
        if themes:
            story.append(Paragraph(f"Detected Themes ({len(themes)}):", styles['SubHeader']))
            for theme, data in themes.items():
                story.append(Paragraph(f"- {theme} (v{data.get('version', 'unknown')})", styles['ReportBody']))

        story.append(Spacer(1, 0.15*inch))

        # Recommendations
        recs = self.results.get('recommendations', [])
        story.append(Paragraph("SECURITY RECOMMENDATIONS", styles['SectionHeader']))
        priority_labels = {0: 'CRITICAL', 1: 'CRITICAL', 2: 'HIGH', 3: 'MEDIUM', 4: 'LOW'}
        for i, rec in enumerate(recs[:15], 1):
            priority = rec.get('priority', 4)
            story.append(Paragraph(f"{i}. [{priority_labels.get(priority, 'LOW')}] {rec['title']}", styles['SubHeader']))
            story.append(Paragraph(rec['description'], styles['ReportBody']))
            story.append(Spacer(1, 0.03*inch))

        # Footer
        story.append(Spacer(1, 0.2*inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
        story.append(Paragraph(
            f"Report generated by WordPress Security Scanner Suite v2.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ParagraphStyle(name='FooterStyle', fontSize=8, textColor=colors.gray, alignment=TA_CENTER)
        ))

        doc.build(story)
        return filepath

    def generate_all(self) -> Dict[str, Path]:
        return {
            'json': self.to_json(),
            'markdown': self.to_markdown(),
            'csv': self.to_csv(),
            'summary': self.to_summary(),
            'pdf': self.to_pdf(),
        }
