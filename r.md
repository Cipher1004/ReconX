ReconX

Advanced Reconnaissance Framework for Security Testing

ReconX is a modular, GUI-driven reconnaissance framework designed to support authorized security assessments, bug bounty engagements, and penetration testing workflows.
It consolidates multiple reconnaissance techniques into a single, streamlined interface, enabling efficient target enumeration and analysis.

Important: ReconX must be used only on systems you own or have explicit permission to test.

Overview

Reconnaissance is a critical phase of any security assessment. ReconX simplifies this process by providing a centralized platform that integrates common recon techniques such as subdomain discovery, port scanning, DNS analysis, and technology fingerprinting.

The tool is designed to balance usability, modularity, and extensibility, making it suitable for both individual researchers and structured security engagements.

Key Capabilities
Reconnaissance Modules

Subdomain Enumeration
Identifies subdomains associated with the target domain.

Port Scanning
Detects open ports and exposed network services.

Directory Bruteforcing
Discovers accessible directories and files.

Technology Detection
Identifies web servers, frameworks, and client-side technologies.

DNS Enumeration
Collects DNS records including A, MX, TXT, and NS.

HTTP Header Analysis
Reviews HTTP response headers and basic security configurations.

Wayback URL Collection
Retrieves historical URLs from public archives.

WHOIS Lookup
Gathers domain registration and ownership data.

Basic Vulnerability Scanning
Performs lightweight checks for common misconfigurations.

Full Recon Mode
Executes all available modules sequentially.

Interface Highlights

Target Scope Input with scope validation

Modular Recon Panel for selective execution

Live Output Console with timestamped logs

Results View for structured findings

Statistics Dashboard for scan metrics

Export Functionality for reporting and documentation

Execution Controls (Start, Stop, Clear)

Installation
Requirements

Python 3.9 or later

Linux environment (Kali Linux recommended)

Setup
git clone https://github.com/yourusername/ReconX.git
cd ReconX
pip install -r requirements.txt

Launch
python reconx.py

Usage

Enter a target domain within the defined scope

Select individual reconnaissance modules or Full Recon

Monitor progress via the Output Console

Review findings in the Results and Statistics tabs

Export data for further analysis or reporting

Intended Audience

ReconX is designed for:

Bug bounty hunters

Penetration testers

Security researchers

Students learning offensive security methodologies

Legal & Ethical Use

This tool is provided as-is for authorized security testing only.

Unauthorized scanning, enumeration, or exploitation of systems may violate:

Local or international laws

Terms of service

Organizational policies

The author assumes no responsibility for misuse of this software.

Project Roadmap

Enhanced asynchronous scanning

Plugin-based module architecture

Advanced vulnerability detection

Automated report generation (HTML / PDF)

Third-party intelligence integrations (e.g., Shodan, Censys)

Improved performance and logging

Contributing

Contributions are encouraged and welcomed.

Fork the repository

Create a feature or fix branch

Commit changes with clear documentation

Submit a pull request

Screenshot

License

This project is released under the MIT License.
See the LICENSE file for details.

Author

ReconX
Advanced Reconnaissance Framework for Ethical Security Testing
