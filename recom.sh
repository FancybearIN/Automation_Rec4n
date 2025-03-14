#!/bin/bash

echo "@fancybearin"
echo "Ankit thakur"

# Ensure the user provides a domain
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain="$1"

# Install dependencies only if not already installed
install_dependencies() {
    echo "[*] Checking and installing dependencies..."
    packages=(python3-pip git curl jq nmap)
    for pkg in "${packages[@]}"; do
        if ! dpkg -s "$pkg" &> /dev/null; then
            echo "[*] Installing $pkg..."
            apt-get install -y "$pkg"
        fi
    done

    python_packages=(subfinder assetfinder chaos alterx amass subjack shodan masscan dirsearch httpx waybackurls ffuf gau katana galer Gxss dalfox gf)
    for py_pkg in "${python_packages[@]}"; do
        if ! pip3 show "$py_pkg" &> /dev/null; then
            echo "[*] Installing $py_pkg..."
            pip3 install "$py_pkg"
        fi
    done
}

# Setup working directories
setup_folders() {
    echo "[*] Setting up directories..."
    cd ~ || exit
    mkdir -p bugbounty/"$domain"
    cd bugbounty/"$domain" || exit
}

# Create output directories
create_output_dirs() {
    echo "[*] Creating output directories..."
    mkdir -p recon_results/"$domain"/{subdomains,takeover,internal_ips,port_scans,directory_bruteforce,extracted_urls,gf_parameters,result}
}

# Subdomain enumeration
enumerate_subdomains() {
    echo "[*] Enumerating subdomains for $domain..."
    subfinder -d "$domain" | tee -a recon_results/"$domain"/subdomains/sub1.txt
    assetfinder --subs-only "$domain" | tee -a recon_results/"$domain"/subdomains/sub2.txt
    amass enum -norecursive -noalts -d "$domain" | tee -a recon_results/"$domain"/subdomains/sub3.txt
    chaos -d "$domain" | tee -a recon_results/"$domain"/subdomains/sub4.txt
    alterx -d "$domain" | tee -a recon_results/"$domain"/subdomains/sub5.txt
    findomain --external-subdomains --output --target "$domain" --unique-output >> recon_results/"$domain"/subdomains/sub6.txt

    cat recon_results/"$domain"/subdomains/*.txt | sort -u > recon_results/"$domain"/subdomains/all_subdomains.txt
}

# Check for subdomain takeovers
check_takeover() {
    echo "[*] Checking for subdomain takeovers..."
    subjack -w recon_results/"$domain"/subdomains/all_subdomains.txt -t 100 -timeout 30 -ssl \
        -c /usr/share/subjack/fingerprints.json -v > recon_results/"$domain"/result/takeover.txt
}

# Extract live URLs
extract_links() {
    echo "[*] Extracting URLs..."
    cat recon_results/"$domain"/subdomains/all_subdomains.txt | httpx | tee recon_results/"$domain"/extracted_urls/live_links.txt
    cat recon_results/"$domain"/subdomains/all_subdomains.txt | httprobe | tee -a recon_results/"$domain"/extracted_urls/live_links.txt
    wait

    cat recon_results/"$domain"/extracted_urls/live_links.txt | sort -u | tee -a recon_results/"$domain"/extracted_urls/unique_links.txt
    cat recon_results/"$domain"/extracted_urls/unique_links.txt | gau | tee -a recon_results/"$domain"/extracted_urls/extracted.txt
    cat recon_results/"$domain"/extracted_urls/unique_links.txt | waybackurls | tee -a recon_results/"$domain"/extracted_urls/extracted.txt
    wait

    cat recon_results/"$domain"/extracted_urls/extracted.txt | sort -u | tee -a recon_results/"$domain"/extracted_urls/cleaned_urls.txt
    cat recon_results/"$domain"/extracted_urls/cleaned_urls.txt | httpx | tee -a recon_results/"$domain"/extracted_urls/final_urls.txt &
    cat recon_results/"$domain"/extracted_urls/cleaned_urls.txt | httprobe -c 10 | tee -a recon_results/"$domain"/extracted_urls/final_urls.txt &
    cat recon_results/"$domain"/extracted_urls/cleaned_urls.txt | katana -d 4 -o recon_results/"$domain"/extracted_urls/final_urls.txt &
    cat recon_results/"$domain"/extracted_urls/cleaned_urls.txt | galer -o recon_results/"$domain"/extracted_urls/final_urls.txt
    wait
}

# Perform GF pattern matching
gf_analysis() {
    echo "[*] Running gf pattern matching..."
    local file="recon_results/$domain/extracted_urls/final_urls.txt"

    # Check if extracted URLs file exists
    if [ ! -f "$file" ]; then
        echo "Error: No extracted URLs found!"
        return
    fi

    # Create a directory to store GF results
    mkdir -p recon_results/"$domain"/gf_parameters

    # Run GF patterns
    for pattern in debug_logic idor img-traversal interestingEXT interestingparams interestingsubs jsvar lfi rce redirect sqli ssrf ssti xss; do
        echo "[*] Running gf for $pattern..."
        
        # Create a directory for each pattern inside gf_parameters
        mkdir -p recon_results/"$domain"/gf_parameters/"$pattern"
        
        # Extract pattern matches and save them in the respective pattern directory
        cat recon_results/"$domain"/extracted_urls/final_urls.txt | gf "$pattern" | tee -a recon_results/"$domain"/gf_parameters/"$pattern"/"$pattern".txt | wc -l
    done
}

# Perform port scanning
perform_port_scan() {
    echo "[*] Performing port scan on $domain..."
    nmap "$domain" -p1-65535 --rate=1000 | tee recon_results/"$domain"/port_scans/ports.txt
}

# Perform directory brute-forcing
directory_bruteforce() {
    echo "[*] Performing directory brute-forcing on $domain..."
    dirsearch -u "$domain" -e * -o recon_results/"$domain"/directory_bruteforce/dirsearch.txt
}

# Testing for vulnerabilities
test_vulnerabilities() {
    echo "[*] Running vulnerability tests..."

    # XSS Testing
    cat recon_results/"$domain"/extracted_urls/final_urls.txt | Gxss | tee -a recon_results/"$domain"/xss/gxss.txt
    cat recon_results/"$domain"/xss/gxss.txt | dalfox pipe | tee -a recon_results/"$domain"/result/dalfox.txt

    # SSRF Testing
    ssrftool -domains recon_results/"$domain"/extracted_urls/unique_links.txt \
        -payloads ~/.git/ssrf-tool/important/payloads.txt -silent=false -paths=true \
        -patterns ~/.git/ssrf-tool/important/patterns.txt | tee -a recon_results/"$domain"/result/ssrf1.txt

    ssrftool -domains recon_results/"$domain"/extracted_urls/cleaned_urls.txt \
        -payloads ~/.git/ssrf-tool/important/payloads.txt -silent=false -paths=true \
        -patterns ~/.git/ssrf-tool/important/patterns.txt | tee -a recon_results/"$domain"/result/ssrf2.txt

    ssrftool -domains recon_results/"$domain"/ssrf/ssrf1.txt \
        -payloads ~/.git/ssrf-tool/important/payloads.txt -silent=false -paths=true \
        -patterns ~/.git/ssrf-tool/important/patterns.txt | tee -a recon_results/"$domain"/result/ssrf3.txt

    #SQl Testing with sqlmap
    bash sqli recon_results/"$domain"/gf_parameters/"$pattern"/sqli.txt | tee -a recon_results/"$domain"/result/sqli_sqlmap_result.txt 

    #nuclei vulerabiltes scanner
    cat recon_results/"$domain"/extracted_urls/final_urls.txt | nuclei -t ./nuclei-templates/ -o recon_results/"$domain"/result/result.txt  
    

}

# Execute all functions in order
install_dependencies
setup_folders
create_output_dirs
enumerate_subdomains
check_takeover
extract_links
gf_analysis  # New function added here
perform_port_scan
directory_bruteforce
test_vulnerabilities

echo "[*] Recon process completed for $domain!"
