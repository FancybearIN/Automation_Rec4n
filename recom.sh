#!/bin/bash

# Display a creative banner
echo "==============================================="
echo " ███╗   ██╗ ██████╗     █████╗ ████████╗██████╗ "
echo " ████╗  ██║██╔═══██╗   ██╔══██╗╚══██╔══╝██╔══██╗"
echo " ██╔██╗ ██║██║   ██║   ███████║   ██║   ██████╔╝"
echo " ██║╚██╗██║██║   ██║   ██╔══██║   ██║   ██╔═══╝ "
echo " ██║ ╚████║╚██████╔╝██╗██║  ██║   ██║   ██║     "
echo " ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝     "
echo "==============================================="
echo "       Next-Gen Advanced Recon Framework       "
echo "==============================================="
echo "                   NG-APTF                     "
echo "==============================================="

# Ensure the user provides a domain
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain="$1"

# Create output directories
create_output_dirs() {
    echo "[*] Creating output directories..."
    mkdir -p recon_results/"$domain"/{subdomains,takeover,internal_ips,port_scans,directory_bruteforce,extracted_urls,gf_parameters,result,xss}
}

# Subdomain enumeration
enumerate_subdomains() {
    echo "[*] Enumerating subdomains for $domain..."
    subfinder -d $domain | tee -a recon_results/$domain/subdomains/sub1.txt
    assetfinder --subs-only $domain | tee -a recon_results/$domain/subdomains/sub2.txt
    echo "$domain" | chaos -key 8efc7ffa-0e70-4bf5-96a8-b60e73e80952 | tee -a recon_results/$domain/subdomains/sub4.txt
    echo "$domain" | alterx | tee -a recon_results/$domain/subdomains/sub5.txt
    wait
    cat recon_results/"$domain"/subdomains/*.txt | sort -u | tee -a recon_results/"$domain"/subdomains/all_subdomains.txt
}

# Check for subdomain takeovers
#check_takeover() {
    echo "[*] Checking for subdomain takeovers..."

    # Filter out invalid entries
    grep -v '^\*' recon_results/$domain/subdomains/all_subdomains.txt > recon_results/$domain/subdomains/all_subdomains_cleaned.txt

    # Run subjack with the cleaned file
    subjack -w recon_results/$domain/subdomains/all_subdomains_cleaned.txt -t 100 -timeout 30 -ssl \
        -c /home/kali/go/pkg/mod/github.com/haccer/subjack@v0.0.0-20201112041112-49c51e57deab/subjack/fingerprint.go -v | tee -a recon_results/$domain/result/takeover.txt
#}

# Extract live URLs
extract_links() {
    echo "[*] Extracting URLs..."
    cat recon_results/$domain/subdomains/all_subdomains.txt | httpx -ports 80,443,8080,8443 | tee -a recon_results/$domain/extracted_urls/live_links.txt
    cat recon_results/$domain/extracted_urls/live_links.txt | sort -u | tee -a recon_results/$domain/extracted_urls/unique_links.txt
    cat recon_results/$domain/extracted_urls/unique_links.txt | gau | tee -a recon_results/$domain/extracted_urls/extracted.txt
    cat recon_results/$domain/extracted_urls/unique_links.txt | waybackurls | tee -a recon_results/$domain/extracted_urls/extracted.txt
    wait

    cat recon_results/$domain/extracted_urls/extracted.txt | sort -u | tee -a recon_results/$domain/extracted_urls/cleaned_urls.txt
    cat recon_results/$domain/extracted_urls/cleaned_urls.txt | httpx | tee -a recon_results/$domain/extracted_urls/final1.txt
    cat recon_results/$domain/extracted_urls/cleaned_urls.txt | httprobe -c 10 | tee -a recon_results/$domain/extracted_urls/final2.txt
    cat recon_results/$domain/extracted_urls/cleaned_urls.txt | katana -d 4 -o recon_results/$domain/extracted_urls/final3.txt
   # cat recon_results/$domain/extracted_urls/cleaned_urls.txt | galer -o recon_results/$domain/extracted_urls/final4.txt
    wait
    cat recon_results/$domain/extracted_urls/*.txt | sort -u | tee -a recon_results/$domain/extracted_urls/final_urls.txt
}

# Perform GF pattern matching
gf_analysis() {
    echo "[*] Running gf pattern matching..."
    local file="recon_results/$domain/extracted_urls/final_urls.txt"

    if [ ! -f "$file" ]; then
        echo "Error: No extracted URLs found!"
        return
    fi

    mkdir -p recon_results/$domain/gf_parameters

    for pattern in debug_logic idor img-traversal interestingEXT interestingparams interestingsubs jsvar lfi rce redirect sqli ssrf ssti xss; do
        echo "[*] Running gf for $pattern..."
        mkdir -p recon_results/$domain/gf_parameters/$pattern
        cat recon_results/$domain/extracted_urls/final_urls.txt | gf $pattern | tee -a recon_results/$domain/gf_parameters/$pattern/$pattern.txt
    done
    wait
}

# Perform port scanning
perform_port_scan() {
    echo "[*] Performing port scan on all subdomains for $domain..."

    # Check if the subdomains file exists
    local subdomains_file="recon_results/$domain/subdomains/all_subdomains.txt"
    if [ ! -f "$subdomains_file" ]; then
        echo "Error: Subdomains file not found at $subdomains_file"
        return
    fi

    # Create output directory for port scans
    mkdir -p recon_results/$domain/port_scans

    # Iterate through each subdomain and perform a port scan
    while read -r subdomain; do
        echo "[*] Scanning ports for $subdomain..."
        nmap -p- -T4 "$subdomain" | tee -a recon_results/$domain/port_scans/${subdomain}_ports.txt
    done < "$subdomains_file"

    echo "[+] Port scanning completed. Results saved in recon_results/$domain/port_scans/"
}

# Perform directory brute-forcing
directory_bruteforce() {
    echo "[*] Performing directory brute-forcing on $domain..."
    while read -r subdomain; do
       dirsearch -u $subdomain -e * -o recon_results/$domain/directory_bruteforce/${subdomain}_dirsearch.txt
    done < recon_results/$domain/subdomains/all_subdomains.txt
    wait
}

# Testing for vulnerabilities
test_vulnerabilities() {
    echo "[*] Running vulnerability tests..."

   # cat recon_results/$domain/extracted_urls/final_urls.txt | Gxss | tee -a recon_results/$domain/xss/gxss.txt
    cat recon_results/$domain/xss/gxss.txt | dalfox pipe | tee -a recon_results/$domain/result/dalfox.txt
    wait

    ssrftool -domains recon_results/$domain/extracted_urls/unique_links.txt \
        -payloads ~/.git/ssrf-tool/important/payloads.txt -silent=false -paths=true \
        -patterns ~/.git/ssrf-tool/important/patterns.txt | tee -a recon_results/$domain/result/ssrf1.txt
    ssrftool -domains recon_results/$domain/extracted_urls/cleaned_urls.txt \
        -payloads ~/.git/ssrf-tool/important/payloads.txt -silent=false -paths=true \
        -patterns ~/.git/ssrf-tool/important/patterns.txt | tee -a recon_results/$domain/result/ssrf2.txt
    wait

    #bash sqli recon_results/$domain/gf_parameters/sqli/sqli.txt | tee -a recon_results/$domain/result/sqli_sqlmap_result.txt
    cat recon_results/$domain/extracted_urls/final_urls.txt | nuclei -t ~/.local/nuclei-templates/ -o recon_results/$domain/result/result.txt
    wait
}

# Execute all functions in order
 create_output_dirs
 enumerate_subdomains
check_takeover 
directory_bruteforce
 extract_links
 gf_analysis
perform_port_scan
test_vulnerabilities

echo "[*] Recon process completed for $domain!"