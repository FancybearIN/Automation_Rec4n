#!/bin/bash

echo "Starting installation of dependencies and setup..."

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update and upgrade the system
update_system() {
    echo "[*] Updating and upgrading the system..."
    sudo apt update -y && sudo apt upgrade -y
    sudo apt autoremove -y && sudo apt autoclean -y
    echo "[+] System update completed."
}

# Install required packages
install_packages() {
    echo "[*] Installing required packages..."
    sudo apt install -y golang xterm nmap dirsearch git curl python3 python3-pip
    echo "[+] Required packages installed."
}

# Install ProjectDiscovery tools
install_projectdiscovery_tools() {
    echo "[*] Installing ProjectDiscovery tools..."
    tools=("subfinder" "httpx" "nuclei" "dnsprobe" "chaos")
    for tool in "${tools[@]}"; do
        if ! command_exists "$tool"; then
            echo "[*] Installing $tool..."
            go install "github.com/projectdiscovery/$tool/v2/cmd/$tool@latest"
        else
            echo "[+] $tool is already installed."
        fi
    done
}

# Install TomNomNom tools
install_tomnomnom_tools() {
    echo "[*] Installing TomNomNom tools..."
    tools=("httprobe" "gf" "anew" "waybackurls")
    for tool in "${tools[@]}"; do
        if ! command_exists "$tool"; then
            echo "[*] Installing $tool..."
            go install "github.com/tomnomnom/$tool@latest"
        else
            echo "[+] $tool is already installed."
        fi
    done
}

# Install additional tools
install_additional_tools() {
    echo "[*] Installing additional tools..."
    if ! command_exists "dalfox"; then
        echo "[*] Installing Dalfox..."
        go install github.com/hahwul/dalfox/v2@latest
    else
        echo "[+] Dalfox is already installed."
    fi

    if ! command_exists "Gxss"; then
        echo "[*] Installing Gxss..."
        go install github.com/KathanP19/Gxss@latest
    else
        echo "[+] Gxss is already installed."
    fi

    if ! command_exists "katana"; then
        echo "[*] Installing Katana..."
        go install github.com/projectdiscovery/katana/cmd/katana@latest
    else
        echo "[+] Katana is already installed."
    fi

    if ! command_exists "ssrftool"; then
        echo "[*] Installing SSRF Tool..."
        git clone https://github.com/R0X4R/ssrf-tool.git
        cd ssrf-tool || exit
        go build ssrftool.go && sudo mv ssrftool /usr/local/bin/
        cd ..
    else
        echo "[+] SSRF Tool is already installed."
    fi

    if ! command_exists "alterx"; then
        echo "[*] Installing AlterX..."
        go install github.com/projectdiscovery/alterx/cmd/alterx@latest
    else
        echo "[+] AlterX is already installed."
    fi

    if ! command_exists "galer"; then
        echo "[*] Installing Galer..."
        go install github.com/dwisiswant0/galer@latest
    else
        echo "[+] Galer is already installed."
    fi
}

# Configure GF patterns
configure_gf_patterns() {
    echo "[*] Configuring GF patterns..."
    if [ ! -d "~/.gf" ]; then
        git clone https://github.com/1ndianl33t/Gf-Patterns
        mkdir -p ~/.gf
        mv Gf-Patterns/*.json ~/.gf
        echo "[+] GF patterns configured."
    else
        echo "[+] GF patterns are already configured."
    fi
}

# Install Python dependencies
install_python_dependencies() {
    echo "[*] Installing Python dependencies..."
    pip3 install -r requirements.txt
    echo "[+] Python dependencies installed."
}

# Move Go binaries to /usr/local/bin
move_go_binaries() {
    echo "[*] Moving Go binaries to /usr/local/bin..."
    if [ -d "$HOME/go/bin" ]; then
        sudo cp "$HOME/go/bin/"* /usr/local/bin/
        echo "[+] Go binaries moved successfully."
    else
        echo "[!] Go binaries directory not found. Skipping..."
    fi
}

# Execute all setup steps
update_system
install_packages
install_projectdiscovery_tools
install_tomnomnom_tools
install_additional_tools
configure_gf_patterns
install_python_dependencies
move_go_binaries

echo "All dependencies installed and setup completed successfully!"