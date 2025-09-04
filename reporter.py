# reporter.py
import os
from datetime import datetime

def generate_report(safe_host, directories, successful_logins, brute_success, otp_brute_success, 
                   manual_used, login_form, otp_form, blocked_usernames, otp_abuse_success, 
                   login_page_url, walf_findings=None):
    
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    
    # Generate timestamp for report
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = f"{report_dir}/report_{safe_host}_{timestamp}.html"
    
    # Modern CSS with a professional design
    css = """
    :root {
        --primary: #2c3e50;
        --secondary: #3498db;
        --success: #27ae60;
        --danger: #e74c3c;
        --warning: #f39c12;
        --info: #3498db;
        --light: #ecf0f1;
        --dark: #2c3e50;
        --gray: #95a5a6;
    }
    
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }
    
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        line-height: 1.6;
        color: #333;
        background-color: #f8f9fa;
        padding: 0;
        margin: 0;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 20px;
    }
    
    .header {
        background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
        color: white;
        padding: 2rem 0;
        margin-bottom: 2rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    .header-content {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    .logo {
        font-size: 2rem;
        font-weight: bold;
    }
    
    .report-meta {
        text-align: right;
        font-size: 0.9rem;
    }
    
    .card {
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
        margin-bottom: 1.5rem;
        overflow: hidden;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    
    .card:hover {
        transform: translateY(-5px);
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
    }
    
    .card-header {
        background-color: var(--light);
        padding: 1rem 1.5rem;
        border-bottom: 1px solid #eee;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    .card-header h2 {
        margin: 0;
        font-size: 1.2rem;
        color: var(--primary);
    }
    
    .card-body {
        padding: 1.5rem;
    }
    
    .card.collapsed .card-body {
        display: none;
    }
    
    .toggle-icon::after {
        content: "▼";
        font-size: 0.8rem;
    }
    
    .card.collapsed .toggle-icon::after {
        content: "►";
    }
    
    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: bold;
        margin-right: 0.5rem;
    }
    
    .status-success {
        background-color: var(--success);
        color: white;
    }
    
    .status-danger {
        background-color: var(--danger);
        color: white;
    }
    
    .status-warning {
        background-color: var(--warning);
        color: white;
    }
    
    .status-info {
        background-color: var(--info);
        color: white;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 1rem 0;
    }
    
    th, td {
        padding: 0.75rem;
        text-align: left;
        border-bottom: 1px solid #eee;
    }
    
    th {
        background-color: var(--light);
        font-weight: 600;
    }
    
    tr:hover {
        background-color: #f8f9fa;
    }
    
    .login-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.75rem;
        border-bottom: 1px solid #eee;
    }
    
    .login-item:last-child {
        border-bottom: none;
    }
    
    .severity-badge {
        display: inline-block;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: bold;
        color: white;
    }
    
    .severity-high {
        background-color: var(--danger);
    }
    
    .severity-medium {
        background-color: var(--warning);
    }
    
    .severity-low {
        background-color: var(--success);
    }
    
    .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
        gap: 1rem;
        margin-bottom: 2rem;
    }
    
    .summary-item {
        background: white;
        border-radius: 8px;
        padding: 1.5rem;
        text-align: center;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
    }
    
    .summary-value {
        font-size: 2rem;
        font-weight: bold;
        margin: 0.5rem 0;
    }
    
    .summary-label {
        color: var(--gray);
        font-size: 0.9rem;
    }
    
    .progress-bar {
        height: 8px;
        background-color: #e9ecef;
        border-radius: 4px;
        overflow: hidden;
        margin: 0.5rem 0;
    }
    
    .progress-fill {
        height: 100%;
        border-radius: 4px;
    }
    
    .security-meter {
        margin: 1.5rem 0;
    }
    
    .meter-label {
        display: flex;
        justify-content: space-between;
        margin-bottom: 0.5rem;
    }
    
    .recommendations {
        background-color: #f8f9fa;
        border-left: 4px solid var(--info);
        padding: 1rem 1.5rem;
        margin: 1rem 0;
    }
    
    .copy-btn {
        background-color: var(--secondary);
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 4px;
        cursor: pointer;
        font-size: 0.8rem;
        margin-left: 1rem;
    }
    
    .copy-btn:hover {
        background-color: #2980b9;
    }
    
    footer {
        text-align: center;
        padding: 2rem 0;
        color: var(--gray);
        font-size: 0.9rem;
        margin-top: 3rem;
        border-top: 1px solid #eee;
    }
    
    @media (max-width: 768px) {
        .summary-grid {
            grid-template-columns: 1fr;
        }
        
        .header-content {
            flex-direction: column;
            text-align: center;
        }
        
        .report-meta {
            text-align: center;
            margin-top: 1rem;
        }
    }
    """
    
    # JavaScript for interactivity
    js = """
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Toggle card sections
        const cardHeaders = document.querySelectorAll('.card-header');
        cardHeaders.forEach(header => {
            header.addEventListener('click', () => {
                const card = header.parentElement;
                card.classList.toggle('collapsed');
            });
        });
        
        // Copy to clipboard functionality
        const copyButtons = document.querySelectorAll('.copy-btn');
        copyButtons.forEach(button => {
            button.addEventListener('click', () => {
                const textToCopy = button.getAttribute('data-copy');
                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalText = button.textContent;
                    button.textContent = 'Copied!';
                    setTimeout(() => {
                        button.textContent = originalText;
                    }, 2000);
                }).catch(err => {
                    console.error('Failed to copy: ', err);
                });
            });
        });
        
        // Expand all/collapse all buttons
        const expandAllBtn = document.getElementById('expand-all');
        const collapseAllBtn = document.getElementById('collapse-all');
        
        if (expandAllBtn && collapseAllBtn) {
            expandAllBtn.addEventListener('click', () => {
                document.querySelectorAll('.card').forEach(card => {
                    card.classList.remove('collapsed');
                });
            });
            
            collapseAllBtn.addEventListener('click', () => {
                document.querySelectorAll('.card').forEach(card => {
                    card.classList.add('collapsed');
                });
            });
        }
    });
    </script>
    """
    
    # Calculate security score (0-100)
    security_score = 80  # Start with a medium score
    
    # Adjust based on findings
    if brute_success:
        security_score -= 30
    if otp_brute_success:
        security_score -= 20
    if otp_abuse_success:
        security_score -= 15
    if blocked_usernames:
        security_score += 10  # Positive - shows they have protection
    
    # Adjust based on WALF findings
    if walf_findings:
        high_sev_count = sum(1 for f in walf_findings if f.get('severity') == 'High')
        medium_sev_count = sum(1 for f in walf_findings if f.get('severity') == 'Medium')
        security_score -= (high_sev_count * 15 + medium_sev_count * 10)
    
    # Ensure score is within bounds
    security_score = max(0, min(100, security_score))
    
    # Determine security level
    if security_score >= 80:
        security_level = "High"
        security_color = "var(--success)"
    elif security_score >= 60:
        security_level = "Medium"
        security_color = "var(--warning)"
    else:
        security_level = "Low"
        security_color = "var(--danger)"
    
    # Generate HTML
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ALFA Security Report - {safe_host}</title>
        <style>{css}</style>
        {js}
    </head>
    <body>
        <div class="header">
            <div class="container">
                <div class="header-content">
                    <div class="logo">ALFA Security Report</div>
                    <div class="report-meta">
                        <div>Target: {safe_host}</div>
                        <div>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="container">
            <div style="display: flex; justify-content: space-between; margin-bottom: 1rem;">
                <button id="expand-all" class="copy-btn">Expand All</button>
                <button id="collapse-all" class="copy-btn">Collapse All</button>
            </div>
            
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-label">Security Score</div>
                    <div class="summary-value" style="color: {security_color};">{security_score}/100</div>
                    <div class="summary-label">{security_level} Security</div>
                </div>
                
                <div class="summary-item">
                    <div class="summary-label">Successful Logins</div>
                    <div class="summary-value">{len(successful_logins)}</div>
                    <div class="summary-label">Accounts Tested</div>
                </div>
                
                <div class="summary-item">
                    <div class="summary-label">Directories Found</div>
                    <div class="summary-value">{len(directories)}</div>
                    <div class="summary-label">During Crawling</div>
                </div>
                
                <div class="summary-item">
                    <div class="summary-label">Blocked Usernames</div>
                    <div class="summary-value">{len(blocked_usernames)}</div>
                    <div class="summary-label">Rate Limiting Detected</div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2>Security Overview</h2>
                    <span class="toggle-icon"></span>
                </div>
                <div class="card-body">
                    <div class="security-meter">
                        <div class="meter-label">
                            <span>Security Level</span>
                            <span>{security_level}</span>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: {security_score}%; background-color: {security_color};"></div>
                        </div>
                    </div>
                    
                    <h3>Summary</h3>
                    <ul>
    """
    
    # Add summary points
    if brute_success:
        html += '<li><span class="status-badge status-danger">Critical</span>Brute force attack successful</li>'
    else:
        html += '<li><span class="status-badge status-success">Good</span>Brute force protection effective</li>'
        
    if otp_brute_success:
        html += '<li><span class="status-badge status-danger">Critical</span>OTP brute force successful</li>'
    elif otp_form:
        html += '<li><span class="status-badge status-success">Good</span>OTP implementation detected</li>'
        
    if otp_abuse_success:
        html += '<li><span class="status-badge status-warning">Warning</span>OTP request abuse possible</li>'
        
    if blocked_usernames:
        html += f'<li><span class="status-badge status-info">Info</span>Rate limiting detected on {len(blocked_usernames)} username(s)</li>'
    else:
        html += '<li><span class="status-badge status-warning">Warning</span>No rate limiting detected</li>'
        
    if walf_findings:
        high_sev = sum(1 for f in walf_findings if f.get('severity') == 'High')
        med_sev = sum(1 for f in walf_findings if f.get('severity') == 'Medium')
        html += f'<li><span class="status-badge status-{"danger" if high_sev > 0 else "warning"}">{"Critical" if high_sev > 0 else "Warning"}</span>Found {high_sev} high and {med_sev} medium severity access control issues</li>'
    
    html += """
                    </ul>
                    
                    <div class="recommendations">
                        <h3>Recommendations</h3>
                        <ul>
    """
    
    # Add recommendations based on findings
    if brute_success:
        html += '<li>Implement account lockout after multiple failed attempts</li>'
        html += '<li>Enforce strong password policies</li>'
        
    if otp_brute_success:
        html += '<li>Implement rate limiting on OTP verification attempts</li>'
        html += '<li>Consider increasing OTP complexity or length</li>'
        
    if otp_abuse_success:
        html += '<li>Implement rate limiting on OTP request endpoints</li>'
        html += '<li>Add CAPTCHA for OTP requests after multiple attempts</li>'
        
    if not blocked_usernames:
        html += '<li>Implement rate limiting on authentication endpoints</li>'
        
    if walf_findings and any(f.get('severity') == 'High' for f in walf_findings):
        html += '<li>Review and strengthen access control mechanisms</li>'
        html += '<li>Implement proper authorization checks on all endpoints</li>'
    
    html += """
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2>Login Form Analysis</h2>
                    <span class="toggle-icon"></span>
                </div>
                <div class="card-body">
    """
    
    if login_form:
        html += f"""
                    <p><strong>URL:</strong> {login_page_url}</p>
                    <p><strong>Action:</strong> {login_form.get('action', 'N/A')}</p>
                    <p><strong>Method:</strong> {login_form.get('method', 'N/A')}</p>
                    
                    <h3>Form Inputs</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Type</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        for inp in login_form.get('inputs', []):
            html += f"""
                            <tr>
                                <td>{inp.get('name', 'N/A')}</td>
                                <td>{inp.get('type', 'N/A')}</td>
                                <td>{inp.get('value', '')}</td>
                            </tr>
            """
            
        html += """
                        </tbody>
                    </table>
        """
    else:
        html += "<p>No login form found during testing.</p>"
        
    html += """
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2>OTP Form Analysis</h2>
                    <span class="toggle-icon"></span>
                </div>
                <div class="card-body">
    """
    
    if otp_form:
        html += f"""
                    <p><strong>Action:</strong> {otp_form.get('action', 'N/A')}</p>
                    <p><strong>Method:</strong> {otp_form.get('method', 'N/A')}</p>
                    
                    <h3>Form Inputs</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Type</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        for inp in otp_form.get('inputs', []):
            html += f"""
                            <tr>
                                <td>{inp.get('name', 'N/A')}</td>
                                <td>{inp.get('type', 'N/A')}</td>
                                <td>{inp.get('value', '')}</td>
                            </tr>
            """
            
        html += """
                        </tbody>
                    </table>
        """
    else:
        html += "<p>No OTP form detected during testing.</p>"
        
    html += """
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2>Successful Logins</h2>
                    <span class="toggle-icon"></span>
                </div>
                <div class="card-body">
    """
    
    if successful_logins:
        html += f"""
                    <p>Found {len(successful_logins)} successful authentication attempts.</p>
                    
                    <div>
                        <strong>Credentials File:</strong> data/successful_logins_{safe_host}.txt
                        <button class="copy-btn" data-copy="data/successful_logins_{safe_host}.txt">Copy Path</button>
                    </div>
                    
                    <h3>Discovered Accounts</h3>
        """
        
        for login in successful_logins:
            status = "FULL_ACCESS" if not login['otp_required'] else "OTP_REQUIRED"
            status_class = "status-success" if not login['otp_required'] else "status-warning"
            censored_pass = login['password'][0] + '*' * (len(login['password']) - 2) + login['password'][-1] if len(login['password']) > 2 else '***'
            
            html += f"""
                    <div class="login-item">
                        <div>
                            <strong>{login['username']}</strong>
                            <span class="status-badge {status_class}">{status}</span>
                        </div>
                        <div>Password: {censored_pass}</div>
                    </div>
            """
            
            html += f"""
                    <div>
                        <strong>Cookies File:</strong> data/cookies_{login['username']}.txt
                        <button class="copy-btn" data-copy="data/cookies_{login['username']}.txt">Copy Path</button>
                    </div>
            """
    else:
        html += "<p>No successful logins during testing.</p>"
        
    html += """
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2>Brute Force Results</h2>
                    <span class="toggle-icon"></span>
                </div>
                <div class="card-body">
    """
    
    if brute_success is not None:
        html += f"""
                    <p class="{'status-danger' if brute_success else 'status-success'}">
                        Brute force attack: {'SUCCESSFUL' if brute_success else 'FAILED'}
                    </p>
        """
        
    if otp_brute_success is not None:
        html += f"""
                    <p class="{'status-danger' if otp_brute_success else 'status-success'}">
                        OTP brute force: {'SUCCESSFUL' if otp_brute_success else 'FAILED'}
                    </p>
        """
        
    if otp_abuse_success is not None:
        html += f"""
                    <p class="{'status-warning' if otp_abuse_success else 'status-success'}">
                        OTP request abuse: {'POSSIBLE' if otp_abuse_success else 'NOT POSSIBLE'}
                    </p>
        """
        
    if manual_used:
        html += "<p>Manual credentials were used during testing.</p>"
        
    html += """
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2>Security Controls</h2>
                    <span class="toggle-icon"></span>
                </div>
                <div class="card-body">
    """
    
    if blocked_usernames:
        html += f"""
                    <p>Rate limiting or account lockout detected for {len(blocked_usernames)} username(s):</p>
                    <ul>
        """
        
        for username in blocked_usernames:
            html += f"<li>{username}</li>"
            
        html += """
                    </ul>
        """
    else:
        html += "<p>No rate limiting or account lockout mechanisms detected.</p>"
        
    html += """
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h2>Discovered Directories</h2>
                    <span class="toggle-icon"></span>
                </div>
                <div class="card-body">
                    <p>Found {len(directories)} directories during crawling:</p>
                    <ul>
    """
    
    for dir in directories:
        html += f"<li>{dir}</li>"
        
    html += """
                    </ul>
                </div>
            </div>
    """
    
    # WALF Findings section
    if walf_findings:
        html += """
            <div class="card">
                <div class="card-header">
                    <h2>Access Control Vulnerabilities</h2>
                    <span class="toggle-icon"></span>
                </div>
                <div class="card-body">
                    <p>Found {} access control issues during testing:</p>
                    <table>
                        <thead>
                            <tr>
                                <th>Scenario</th>
                                <th>Target</th>
                                <th>Value</th>
                                <th>Severity</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
        """.format(len(walf_findings))
        
        for finding in walf_findings:
            severity_class = "severity-low"
            if finding.get('severity') == 'High':
                severity_class = "severity-high"
            elif finding.get('severity') == 'Medium':
                severity_class = "severity-medium"
                
            html += f"""
                            <tr>
                                <td>{finding.get('scenario', 'N/A')}</td>
                                <td>{finding.get('target', 'N/A')}</td>
                                <td>{finding.get('value', 'N/A')}</td>
                                <td><span class="severity-badge {severity_class}">{finding.get('severity', 'N/A')}</span></td>
                                <td>{finding.get('response', {}).get('status', 'N/A')}</td>
                            </tr>
            """
        
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
        """
    
    html += """
        </div>
        
        <footer>
            <div class="container">
                <p>Generated by ALFA (Access & Logic Flaw Analyzer)</p>
                <p>Raihan Rinto Andiansyah & Ahmed Haykal Hifzhan Rachmady</p>
            </div>
        </footer>
    </body>
    </html>
    """
    
    # Write the report to file
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"[+] Modern security report saved to {report_path}")
    return report_path