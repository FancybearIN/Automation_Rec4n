#!/bin/bash

# Function to copy required binaries
install_tools() {
    sudo cp gg /usr/local/bin
}

# System update and cleanup
system_update() {
    sudo apt update -y && sudo apt upgrade -y
    sudo apt autoremove -y && sudo apt autoclean -y && sudo apt dist-upgrade -y
}

# Install necessary packages
install_dependencies() {
    sudo apt install -y golang xterm amass
}

# Install ProjectDiscovery tools
install_projectdiscovery() {
    go install github.com/projectdiscovery/dnsprobe@latest  
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/projectdiscovery/assetfinder/v2/cmd/assetfinder@latest
}

# Install TomNomNom and related tools
install_tomnomnom() {
    go install github.com/tomnomnom/httprobe@latest
    go install github.com/tomnomnom/gf@latest
    go install github.com/tomnomnom/anew@latest
    go install github.com/tomnomnom/waybackurls@latest
    go install github.com/ffuf/ffuf@latest
    go install github.com/lc/gau/v2/cmd/gau@latest
    go install github.com/hahwul/dalfox/v2@latest
    go install github.com/dwisiswant0/galer@latest
    go install github.com/KathanP19/Gxss@latest
    go install github.com/projectdiscovery/katana/cmd/katana@latest
    go install github.com/haccer/subjack@latest
}

# Install GitHub-based tools
install_github_tools() {
    git clone https://github.com/R0X4R/ssrf-tool.git
    cd ssrf-tool
    go build ssrftool.go && sudo mv ssrftool /usr/bin/
    cd ..
}

# Configure Gf-Patterns
configure_gf_patterns() {
    git clone https://github.com/1ndianl33t/Gf-Patterns
    mkdir -p ~/.gf
    mv Gf-Patterns/*.json ~/.gf
}

# Move installed Go binaries to /usr/local/bin
move_go_binaries() {
    read -p "Enter your username: " username
    sudo cp /home/$username/go/bin/* /usr/local/bin
}

# Execute functions in order
install_tools
system_update
install_dependencies
install_projectdiscovery
install_tomnomnom
install_github_tools
configure_gf_patterns
move_go_binaries

echo "Installation and configuration completed successfully!"
