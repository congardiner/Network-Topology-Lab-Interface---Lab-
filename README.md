# Network Topology Viewer (Personal Lab Project)

This is an interactive web app (streamlit-based) for visualizing lab topologies from YAML files, which has also been uploaded with topologies (sampled) to showcase basic network topology protocols and frameworks to use as a review asset in preparing for certifications.

Built with **Streamlit**, **NetworkX**, and **PyVis**, this tool lets you:

- Define lab sites, routers, switches, and links in YAML.
- Visualize the topology as an interactive graph (hover to see details).
- Optionally run ICMP ping checks to color nodes by status.
- Filter by site and by link type (physical vs logical).

## Features

- **YAML-driven topology**
  - Sites (e.g., `HQ`, `Branch1`).
  - Nodes with: `id`, `name`, `site`, `role` (router/switch/etc), `mgmt_ip`, optional `routing_protocol`, and `vlans`.
  - Links with: `id`, `from`, `to`, `description`, `ip_a`, `ip_b`, optional `link_type` (physical/logical) and `vlan`.
- **Status-aware nodes**
  - Optional ping checks (using `ping3`) against management IPs.
  - Nodes colored by role, with hover tooltip showing routing protocol, VLANs, and status.
- **Logical vs physical view**
  - Toggle between:
    - `All links`
    - `Physical only`
    - `Logical only` (for tunnels, SVIs, etc., when marked in YAML).

## Quick start

From the project root:

```bash
cd "topology_viewer"
python -m venv .venv
# On Windows PowerShell
. .venv/Scripts/Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Streamlit will start a local web server (by default at `http://localhost:8501`) and open your browser. The app **runs in the browser**, but is **started from the terminal** with the `streamlit run` command.

> Note: This app is written to be compatible with Python 3.9+.

## Using the app

1. **Topology input**
   - In the sidebar, either:
     - Upload your own YAML file, or
     - Use the bundled sample: [sample_topology.yaml](sample_topology.yaml).
2. **Display options**
   - Enable/disable live ping checks of management IPs.
   - Filter by **site** (e.g., HQ vs Branch).
   - Choose which **links** to display (all/physical/logical).
3. **Explore the topology**
   - Hover over nodes to see:
     - Name, role, site, management IP.
     - Routing protocol tag (e.g., OSPF, EIGRP, static).
     - VLANs defined on the device.
     - Live status (up/down/unknown, if ping is enabled).
   - Hover over links to see:
     - Description, IPs on each end.
     - Link type (physical/logical) and VLAN (if provided).

## YAML schema overview

Minimal example:

```yaml
sites:
  - id: HQ
    name: Headquarters

nodes:
  - id: R1
    name: R1-HQ
    site: HQ
    role: router
    mgmt_ip: 192.168.0.1
    routing_protocol: ospf   # optional
    vlans: [10, 20]         # optional

links:
  - id: WAN1
    from: R1
    to: R2
    description: HQ-BR1 WAN
    ip_a: 172.16.0.1/30
    ip_b: 172.16.0.2/30
    link_type: physical      # optional; 'physical' or 'logical'
    vlan: 10                 # optional
```

Fields marked *optional* can be omitted without breaking the app.

## Future Enhancements to be made:

Ideas for future enhancements:

- Add SNMP-based interface status or utilization.
- Tag links with OSPF areas or EIGRP AS numbers and color-code them.
- Export diagrams or snapshots for use in change tickets or documentation.
