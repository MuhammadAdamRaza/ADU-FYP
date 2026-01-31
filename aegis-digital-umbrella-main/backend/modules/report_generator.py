import io
import re
import html
import logging
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from datetime import datetime

logger = logging.getLogger(__name__)

def sanitize_text_for_pdf(text: str) -> str:
    """Sanitize text for ReportLab by removing HTML tags and special characters."""
    if not text:
        return "No content available"
    try:
        # Log raw text for debugging
        logger.debug(f"Raw text before sanitization: {text[:200]}")
        
        # Remove HTML tags using regex
        clean_text = re.sub(r'<[^>]+>', '', text)
        # Escape remaining HTML entities
        clean_text = html.escape(clean_text)
        # Replace problematic characters
        clean_text = clean_text.replace('\r', '').replace('\n', ' ').replace('\t', ' ')
        # Remove control characters
        clean_text = re.sub(r'[\x00-\x1F\x7F]', '', clean_text)
        # Truncate to avoid overwhelming ReportLab
        clean_text = clean_text[:1000]
        # Log sanitized text
        logger.debug(f"Sanitized text: {clean_text[:200]}")
        return clean_text if clean_text.strip() else "No content available"
    except Exception as e:
        logger.error(f"Sanitization error: {str(e)}")
        return "Error processing content"

def generate_pdf_report(scan_result) -> bytes:
    """Generate a PDF report for scan results."""
    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        story.append(Paragraph("AEGIS Security Scan Report", title_style))
        story.append(Spacer(1, 12))

        # Scan Information
        info_style = ParagraphStyle(
            'InfoStyle',
            parent=styles['Normal'],
            fontSize=12,
            spaceAfter=6
        )
        
        story.append(Paragraph(f"<b>URL:</b> {sanitize_text_for_pdf(scan_result.url)}", info_style))
        story.append(Paragraph(f"<b>Scan Date:</b> {scan_result.created_at.strftime('%Y-%m-%d %H:%M:%S')}", info_style))
        story.append(Paragraph(f"<b>Scan Types:</b> {', '.join(scan_result.scan_types)}", info_style))
        story.append(Spacer(1, 20))

        # Summary
        summary_style = ParagraphStyle(
            'SummaryStyle',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkred
        )
        story.append(Paragraph("Executive Summary", summary_style))
        
        summary_data = [
            ['Total Vulnerabilities', str(scan_result.total_vulnerabilities)],
            ['High Severity', str(scan_result.high_severity_count)],
            ['Medium Severity', str(scan_result.medium_severity_count)],
            ['Low Severity', str(scan_result.low_severity_count)]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))

        # Vulnerabilities
        if scan_result.vulnerabilities:
            vuln_style = ParagraphStyle(
                'VulnStyle',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                textColor=colors.darkred
            )
            story.append(Paragraph("Detected Vulnerabilities", vuln_style))
            
            for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                vuln_header_style = ParagraphStyle(
                    'VulnHeaderStyle',
                    parent=styles['Heading3'],
                    fontSize=14,
                    spaceAfter=6,
                    textColor=colors.red if vuln.severity == 'High' else colors.orange if vuln.severity == 'Medium' else colors.green
                )
                
                story.append(Paragraph(f"{i}. {sanitize_text_for_pdf(vuln.type)} - {vuln.severity} Severity", vuln_header_style))
                story.append(Paragraph(f"<b>Description:</b> {sanitize_text_for_pdf(vuln.description)}", styles['Normal']))
                story.append(Paragraph(f"<b>Location:</b> {sanitize_text_for_pdf(vuln.location)}", styles['Normal']))
                story.append(Paragraph(f"<b>Evidence:</b> {sanitize_text_for_pdf(vuln.evidence)}", styles['Normal']))
                story.append(Paragraph(f"<b>Recommendation:</b> {sanitize_text_for_pdf(vuln.recommendation)}", styles['Normal']))
                story.append(Spacer(1, 12))

        # AI Recommendations
        if scan_result.ai_recommendations:
            ai_style = ParagraphStyle(
                'AIStyle',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                textColor=colors.darkblue
            )
            story.append(Paragraph("AI-Powered Recommendations", ai_style))
            
            for i, recommendation in enumerate(scan_result.ai_recommendations, 1):
                story.append(Paragraph(f"{i}. {sanitize_text_for_pdf(recommendation)}", styles['Normal']))
                story.append(Spacer(1, 6))

        # Footer
        story.append(Spacer(1, 30))
        footer_style = ParagraphStyle(
            'FooterStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.grey
        )
        story.append(Paragraph("Generated by AEGIS Digital Umbrella - Advanced Cybersecurity Scanner", footer_style))
        story.append(Paragraph(f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", footer_style))

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
        
    except Exception as e:
        logger.error(f"PDF generation error: {str(e)}")
        # Return a simple error PDF
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = [Paragraph("Error generating report. Please try again.", styles['Normal'])]
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

