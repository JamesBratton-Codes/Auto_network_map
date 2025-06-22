# Auto Network Map

A Python-based tool to automatically discover network devices, collect detailed inventory data, and generate a visual topology map. This script recursively crawls the network using CDP, prompts for credentials for newly discovered devices, and aggregates data into a comprehensive Excel report.

## Features

-   **Recursive Network Discovery:** Starts from a seed device and automatically finds neighbors via CDP.
-   **Multi-vendor Support (via Netmiko):** Primarily built for Cisco IOS, but easily extensible.
-   **Detailed Port-level Data:** Gathers status, speed, duplex, errors, description, VLAN, and more for each active port.
-   **ARP & MAC Table Collection:** Discovers connected end hosts for each device.
-   **Interactive Credential Management:** Securely prompts for credentials for each new device and caches them for the current session.
-   **Comprehensive Excel Reporting:**
    -   **Devices Sheet:** A hierarchical view of all discovered devices, their connected ARP/MAC entries, and detailed port-level info.
    -   **Links Sheet:** A clear summary of all infrastructure links between network devices.
-   **Visual Network Diagram:** Automatically generates a `.png` network map using Graphviz.

## Prerequisites

-   Python 3.8+
-   **Graphviz:** The graphviz engine must be installed on your system and available in your system's PATH.
    -   **Windows:** Download from the [official site](https://graphviz.org/download/) and ensure the `bin` directory is in your PATH.
    -   **macOS:** `brew install graphviz`
    -   **Linux (Debian/Ubuntu):** `sudo apt-get install graphviz`

## Installation & Usage

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/JamesBratton-Codes/Auto_network_map.git
    cd Auto_network_map
    ```

2.  **Run the bootstrap script:**
    This will create a Python virtual environment, install all required dependencies, and run the main script.

    -   **On Windows:**
        ```powershell
        .\bootstrap.bat
        ```
    -   **On macOS/Linux (you'll need to create a `bootstrap.sh`):**
        ```bash
        # (See bootstrap.sh example below)
        chmod +x bootstrap.sh
        ./bootstrap.sh
        ```

3.  **Follow the prompts:**
    -   Enter the IP address of your seed (starting) device.
    -   Enter the credentials for each device as prompted.

## Example Output

The script will generate two files:

-   `network_inventory.xlsx`: A detailed Excel report with sheets for Devices, Links, and connected endpoints.
-   `network_map.png`: A visual diagram of the network topology.
  
![network_map](https://github.com/user-attachments/assets/a3b7b0ba-d1d8-4577-a94b-945c0f9f229a)

*(You could include a sample image of your map here)*

---

### Example `bootstrap.sh` for macOS/Linux

```bash
#!/bin/bash
set -e

# Check for Python
if ! command -v python3 &> /dev/null
then
    echo "Python3 is not installed or not in PATH."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip and install requirements
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Run the main script
echo "Running network discovery script..."
python3 network_discover.py

deactivate
echo "Script finished."
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 
