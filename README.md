# **Automated Bug Bounty Reconnaissance Tool**
This script automates the process of performing reconnaissance for bug bounty programs. It utilizes various tools to gather information about a target domain and identify potential vulnerabilities.

**Prerequisites:**

* **Linux Operating System:** This script is designed to run on Linux systems.
* **Go Programming Language:** The script requires Go to be installed.
* **Git:** Git is required to clone the necessary repositories.

**Installation:**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/FancybearIN/Automation_Rec4n.git && cd Automation_Rec4n
2. **Run the installation script:**
     ```bash   
        sudo bash install.sh

3. **This script will install all the necessary dependencies and tools.**

        Usage:

4.  **Run the tester script:**

        ./tester.sh target.com

## Replace target.com with the domain you want to scan.
Features:

### **Subdomain Enumeration:**

- Uses subfinder, assetfinder, amass, and findomain to discover subdomains.

### **Link Extraction:**

Uses httpx, httprobe, gau, waybackurls, katana, galer to extract links from the discovered subdomains.

### **Vulnerability Testing:**

Uses Gxss, dalfox, ssrftool to test for XSS and SSRF vulnerabilities.

## **Workflow:**

- **Subdomain Enumeration: The script starts by enumerating subdomains using various tools.**

- **Link Extraction: It then extracts links from the discovered subdomains using a combination of tools.**

- **Vulnerability Testing: Finally, it performs basic vulnerability testing for XSS and SSRF.**

## **Note:**

This script is a starting point for bug bounty reconnaissance. You may need to adjust the tools and techniques used based on your specific needs.
The script uses various tools that may require additional configuration or setup.
It is important to use this script responsibly and ethically.
Disclaimer:

**This script is provided for educational purposes only. The author is not responsible for any misuse or damage caused by this script.**

