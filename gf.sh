#!/bin/bash

gf_analysis() {
    local domain=vulnweb.com
    echo "[*] Running gf pattern matching for $domain..."
    local file="recon_results/$domain/extracted_urls/final_urls.txt"

    if [ ! -f "$file" ]; then
        echo "Error: No extracted URLs found!"
        return
    fi

    mkdir -p recon_results/$domain/gf_parameters

    for pattern in debug_logic idor img-traversal interestingEXT interestingparams interestingsubs jsvar lfi rce redirect sqli ssrf ssti xss; do
        echo "[*] Running gf for $pattern..."
        mkdir -p recon_results/$domain/gf_parameters/$pattern
        cat "$file" | gf $pattern | tee -a recon_results/$domain/gf_parameters/$pattern/$pattern.txt
    done
    wait
}

# Call the function
gf_analysis