from pathlib import Path
from typing import Optional
import random

import networkx as nx
import pandas as pd
import streamlit as st
import yaml
from ping3 import ping
from pyvis.network import Network
import streamlit.components.v1 as components


BASE_DIR = Path(__file__).parent
DEFAULT_TOPOLOGY = BASE_DIR / "sample_topology.yaml"
EXAMPLE_SUFFIX = "_topology.yaml"


CCNA_TOPICS = {
    "VLANs & Trunking": {
        "summary": "Segmentation of a Layer 2 network into separate broadcast domains and carrying multiple VLANs over a single physical link.",
        "key_points": [
            "Access ports belong to a single VLAN; trunk ports carry multiple VLANs.",
            "802.1Q tagging is used on trunk links to differentiate VLAN traffic.",
            "Native VLAN frames are sent untagged on many Cisco platforms.",
        ],
        "terms": {
            "VLAN": "Virtual LAN; a logical broadcast domain on a switch.",
            "Trunk": "A link that carries traffic for multiple VLANs using tagging.",
            "Access port": "Switch port assigned to a single VLAN for end devices.",
        },
        "related_examples": ["Trunk Ports Topology", "Router On A Stick Topology"],
    },
    "Router-on-a-stick": {
        "summary": "Using a single physical router interface with subinterfaces to route between multiple VLANs.",
        "key_points": [
            "Subinterfaces are configured with encapsulation dot1Q and VLAN IDs.",
            "Each VLAN uses the router subinterface IP as its default gateway.",
            "The switch port connected to the router operates as an 802.1Q trunk.",
        ],
        "terms": {
            "Subinterface": "Logical interface on a router derived from a physical interface.",
            "Default gateway": "Router IP address used by hosts to leave their subnet.",
        },
        "related_examples": ["Router On A Stick Topology"],
    },
    "Single-area OSPF": {
        "summary": "Link-state routing protocol using SPF algorithm with all routers in area 0.",
        "key_points": [
            "Routers form adjacencies with neighbors and exchange LSAs.",
            "All routers in a single area share the same LSDB.",
            "OSPF uses cost (based on bandwidth) as the metric.",
        ],
        "terms": {
            "LSA": "Link-State Advertisement; describes links and networks.",
            "Area 0": "Backbone area that must exist in every OSPF network.",
            "DR/BDR": "Designated/Backup Designated Router on multiaccess networks.",
        },
        "related_examples": ["Single Area Ospf Topology"],
    },
    "IP Addressing & Subnetting": {
        "summary": "Planning IPv4 addressing, subnet masks, and summarization.",
        "key_points": [
            "Subnet mask determines the network and host portions of an IP address.",
            "Smaller subnets reduce broadcast domains but increase routing entries.",
            "Use consistent addressing plans for WAN links vs LAN segments.",
        ],
        "terms": {
            "CIDR": "Classless Inter-Domain Routing; slash notation for masks.",
            "Prefix length": "Number of bits used for the network portion (e.g., /24).",
        },
        "related_examples": [
            "Sample Topology", "Router On A Stick Topology", "Single Area Ospf Topology",
        ],
    },
}


def load_topology(
    uploaded_file=None,
    *,
    file_path: Optional[Path] = None,
    data_obj: Optional[dict] = None,
) -> dict:
    """Load topology from one of three sources.

    Priority:
    - data_obj (already constructed dict)
    - file_path (Path on disk)
    - uploaded_file (Streamlit UploadedFile)
    - fallback to DEFAULT_TOPOLOGY
    """

    if data_obj is not None:
        return data_obj

    if file_path is not None:
        return yaml.safe_load(file_path.read_text(encoding="utf-8"))

    if uploaded_file is not None:
        return yaml.safe_load(uploaded_file.read())

    with DEFAULT_TOPOLOGY.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def list_example_files() -> dict:
    """Return a mapping of human-friendly names to example YAML Paths."""
    examples = {}
    for path in BASE_DIR.glob("*.yaml"):
        if path.name == DEFAULT_TOPOLOGY.name:
            continue
        # Only treat files matching *_topology.yaml as curated examples
        if not path.name.endswith(EXAMPLE_SUFFIX):
            continue
        label = path.name.replace(EXAMPLE_SUFFIX, "").replace("_", " ").title()
        examples[label] = path
    return dict(sorted(examples.items(), key=lambda x: x[0].lower()))


def generate_ccna_lab(topic: str) -> dict:
    """Generate a small CCNA-style lab topology in memory.

    This keeps shapes simple but slightly randomizes VLANs/IPs.
    """

    if topic == "Router-on-a-stick":
        vlan10 = random.choice([10, 110, 210])
        vlan20 = vlan10 + 10
        return {
            "sites": [
                {"id": "HQ", "name": "Headquarters"},
            ],
            "nodes": [
                {
                    "id": "R1",
                    "name": "R1-HQ",
                    "site": "HQ",
                    "role": "router",
                    "mgmt_ip": "192.168.100.1",
                    "routing_protocol": "static",
                    "vlans": [vlan10, vlan20],
                },
                {
                    "id": "SW1",
                    "name": "SW1-HQ",
                    "site": "HQ",
                    "role": "switch",
                    "mgmt_ip": "192.168.100.2",
                    "vlans": [vlan10, vlan20],
                },
                {
                    "id": "PC1",
                    "name": "PC1-VLAN{}".format(vlan10),
                    "site": "HQ",
                    "role": "host",
                    "mgmt_ip": f"192.168.{vlan10}.10",
                    "vlans": [vlan10],
                },
                {
                    "id": "PC2",
                    "name": "PC2-VLAN{}".format(vlan20),
                    "site": "HQ",
                    "role": "host",
                    "mgmt_ip": f"192.168.{vlan20}.10",
                    "vlans": [vlan20],
                },
            ],
            "links": [
                {
                    "id": "TRUNK1",
                    "from": "R1",
                    "to": "SW1",
                    "description": "Router-on-a-stick trunk",
                    "ip_a": "192.168.100.1/24",
                    "ip_b": "192.168.100.2/24",
                    "link_type": "physical",
                },
                {
                    "id": "ACCESS_PC1",
                    "from": "SW1",
                    "to": "PC1",
                    "description": f"Access link VLAN {vlan10}",
                    "ip_a": f"192.168.{vlan10}.1/24",
                    "ip_b": f"192.168.{vlan10}.10/24",
                    "link_type": "physical",
                    "vlan": vlan10,
                },
                {
                    "id": "ACCESS_PC2",
                    "from": "SW1",
                    "to": "PC2",
                    "description": f"Access link VLAN {vlan20}",
                    "ip_a": f"192.168.{vlan20}.1/24",
                    "ip_b": f"192.168.{vlan20}.10/24",
                    "link_type": "physical",
                    "vlan": vlan20,
                },
            ],
        }

    if topic == "Trunk & access VLANs":
        vlan_list = [10, 20, 30]
        return {
            "sites": [
                {"id": "CAMPUS", "name": "Main Campus"},
            ],
            "nodes": [
                {
                    "id": "SW1",
                    "name": "SW1-Access",
                    "site": "CAMPUS",
                    "role": "switch",
                    "mgmt_ip": "10.1.1.2",
                    "vlans": vlan_list,
                },
                {
                    "id": "SW2",
                    "name": "SW2-Distribution",
                    "site": "CAMPUS",
                    "role": "switch",
                    "mgmt_ip": "10.1.1.3",
                    "vlans": vlan_list,
                },
                {
                    "id": "R1",
                    "name": "R1-Gateway",
                    "site": "CAMPUS",
                    "role": "router",
                    "mgmt_ip": "10.1.1.1",
                    "routing_protocol": "static",
                    "vlans": vlan_list,
                },
            ],
            "links": [
                {
                    "id": "TRUNK_SW1_SW2",
                    "from": "SW1",
                    "to": "SW2",
                    "description": "Switch trunk carrying VLANs 10,20,30",
                    "ip_a": "10.1.1.2/30",
                    "ip_b": "10.1.1.3/30",
                    "link_type": "physical",
                },
                {
                    "id": "TRUNK_SW2_R1",
                    "from": "SW2",
                    "to": "R1",
                    "description": "Trunk to router gateway",
                    "ip_a": "10.1.1.3/30",
                    "ip_b": "10.1.1.1/30",
                    "link_type": "physical",
                },
            ],
        }

    # Default: simple single-area OSPF triangle
    base = 100
    return {
        "sites": [
            {"id": "RING", "name": "OSPF Ring"},
        ],
        "nodes": [
            {
                "id": "R1",
                "name": "R1-Core",
                "site": "RING",
                "role": "router",
                "mgmt_ip": f"10.{base}.1.1",
                "routing_protocol": "ospf",
            },
            {
                "id": "R2",
                "name": "R2-Core",
                "site": "RING",
                "role": "router",
                "mgmt_ip": f"10.{base}.2.1",
                "routing_protocol": "ospf",
            },
            {
                "id": "R3",
                "name": "R3-Core",
                "site": "RING",
                "role": "router",
                "mgmt_ip": f"10.{base}.3.1",
                "routing_protocol": "ospf",
            },
        ],
        "links": [
            {
                "id": "R1-R2",
                "from": "R1",
                "to": "R2",
                "description": "OSPF area 0 link",
                "ip_a": f"10.{base}.12.1/30",
                "ip_b": f"10.{base}.12.2/30",
                "link_type": "physical",
            },
            {
                "id": "R2-R3",
                "from": "R2",
                "to": "R3",
                "description": "OSPF area 0 link",
                "ip_a": f"10.{base}.23.1/30",
                "ip_b": f"10.{base}.23.2/30",
                "link_type": "physical",
            },
            {
                "id": "R3-R1",
                "from": "R3",
                "to": "R1",
                "description": "OSPF area 0 link",
                "ip_a": f"10.{base}.31.1/30",
                "ip_b": f"10.{base}.31.2/30",
                "link_type": "physical",
            },
        ],
    }


def build_graph(data: dict) -> nx.Graph:
    g = nx.Graph()

    # Add sites as graph-level metadata (optional)
    sites = {s["id"]: s for s in data.get("sites", [])}

    for node in data.get("nodes", []):
        g.add_node(
            node["id"],
            label=node.get("name", node["id"]),
            site=node.get("site"),
            role=node.get("role"),
            mgmt_ip=node.get("mgmt_ip"),
            routing_protocol=node.get("routing_protocol"),
            vlans=node.get("vlans"),
            site_name=sites.get(node.get("site"), {}).get("name"),
        )

    for link in data.get("links", []):
        g.add_edge(
            link["from"],
            link["to"],
            id=link.get("id"),
            description=link.get("description"),
            ip_a=link.get("ip_a"),
            ip_b=link.get("ip_b"),
            link_type=link.get("link_type"),
            vlan=link.get("vlan"),
        )

    return g


def run_ping_check(ip: Optional[str], timeout: float = 1.0) -> str:
    if not ip:
        return "unknown"

    # Strip mask if present
    ip_only = ip.split("/")[0]

    try:
        rtt = ping(ip_only, timeout=timeout)
    except PermissionError:
        # Some OS require admin for ICMP; treat as unknown
        return "unknown"
    except Exception:
        return "down"

    if rtt is None:
        return "down"
    return "up"


def evaluate_status(g: nx.Graph, enable_ping: bool, selected_site: Optional[str]):
    node_status = {}

    for node_id, attrs in g.nodes(data=True):
        site = attrs.get("site")
        if selected_site and site != selected_site:
            # Still compute status, but you might hide in UI later
            pass

        status = "unknown"
        if enable_ping:
            status = run_ping_check(attrs.get("mgmt_ip"))
        node_status[node_id] = status

    return node_status


def build_pyvis_network(
    g: nx.Graph,
    node_status: dict,
    selected_site: Optional[str],
    link_view_mode: str,
):
    net = Network(height="650px", width="100%", bgcolor="#0f172a", font_color="white")
    net.barnes_hut()

    role_colors = {
        "router": "#22c55e",
        "switch": "#3b82f6",
        "firewall": "#f97316",
        "server": "#eab308",
    }

    status_border = {
        "up": "#22c55e",
        "down": "#ef4444",
        "unknown": "#6b7280",
    }

    for node_id, attrs in g.nodes(data=True):
        site = attrs.get("site")
        if selected_site and site != selected_site:
            continue

        status = node_status.get(node_id, "unknown")
        color = role_colors.get(attrs.get("role"), "#38bdf8")
        border = status_border.get(status, "#6b7280")

        title_lines = [
            f"<b>{attrs.get('label', node_id)}</b>",
            f"Role: {attrs.get('role', 'n/a')}",
            f"Site: {attrs.get('site_name') or attrs.get('site') or 'n/a'}",
            f"Mgmt IP: {attrs.get('mgmt_ip') or 'n/a'}",
            f"Routing: {attrs.get('routing_protocol') or 'n/a'}",
            f"VLANs: {', '.join(str(v) for v in (attrs.get('vlans') or [])) or 'n/a'}",
            f"Status: {status}",
        ]

        net.add_node(
            node_id,
            label=attrs.get("label", node_id),
            title="<br/>".join(title_lines),
            color=color,
            borderWidth=3,
            borderWidthSelected=4,
            shape="dot",
            size=20,
            font={"size": 16},
            # Custom style for status via color highlight
            
        )

    for u, v, attrs in g.edges(data=True):
        if selected_site:
            # Only show links where both ends are in selected site
            if g.nodes[u].get("site") != selected_site or g.nodes[v].get("site") != selected_site:
                continue

        # Filter by link type based on view mode
        link_type = (attrs.get("link_type") or "").lower()
        if link_view_mode == "Physical only" and link_type == "logical":
            continue
        if link_view_mode == "Logical only" and (link_type == "physical" or not link_type):
            continue

        desc = attrs.get("description") or attrs.get("id") or "link"
        ip_a = attrs.get("ip_a") or ""
        ip_b = attrs.get("ip_b") or ""

        vlan = attrs.get("vlan")
        vlan_line = f"VLAN: {vlan}" if vlan else ""
        lt_line = f"Link type: {link_type or 'unspecified'}"

        title_parts = [f"<b>{desc}</b>", f"{u}: {ip_a}", f"{v}: {ip_b}", lt_line]
        if vlan_line:
            title_parts.append(vlan_line)

        title = "<br/>".join(title_parts)

        net.add_edge(u, v, title=title, color="#64748b")

    return net


def render_topology_page():
    st.title("Network Topology Viewer (CCNA Lab)")

    with st.sidebar:
        st.header("Topology Selection")

        examples = list_example_files()
        random_topics = [
            "Router-on-a-stick",
            "Trunk & access VLANs",
            "Single-area OSPF",
        ]

        options = ["Sample: HQ/Branch"]
        for name in examples.keys():
            options.append(f"Example: {name}")
        for topic in random_topics:
            options.append(f"Random: {topic}")
        options.append("Upload: custom YAML")

        selected_topology = st.selectbox("Topology", options)

        uploaded = None
        file_path: Optional[Path] = None
        data_obj = None

        if selected_topology == "Sample: HQ/Branch":
            file_path = DEFAULT_TOPOLOGY
        elif selected_topology.startswith("Example: "):
            example_name = selected_topology.replace("Example: ", "")
            file_path = examples.get(example_name)
        elif selected_topology.startswith("Random: "):
            topic = selected_topology.replace("Random: ", "")
            data_obj = generate_ccna_lab(topic)
        else:  # Upload
            uploaded = st.file_uploader("Upload topology YAML", type=["yml", "yaml"])

        with st.expander("Sample topology (HQ/Branch)", expanded=selected_topology == "Sample: HQ/Branch"):
            st.code(DEFAULT_TOPOLOGY.read_text(encoding="utf-8"), language="yaml")

        st.header("Display Options")
        enable_ping = st.checkbox(
            "Run live ping checks (mgmt IPs)",
            value=False,
            help="Uses ICMP ping from this machine; may need admin rights on some OS.",
        )

    data = load_topology(uploaded_file=uploaded, file_path=file_path, data_obj=data_obj)

    if not data:
        st.error("No topology data loaded.")
        return

    g = build_graph(data)

    sites = sorted({n[1].get("site") for n in g.nodes(data=True) if n[1].get("site")})
    site_display = ["All sites"] + sites if sites else ["All sites"]

    col_filters, col_summary = st.columns([1, 2])

    with col_filters:
        st.subheader("Filters")
        site_choice = st.selectbox("Site", site_display)
        selected_site = None if site_choice == "All sites" else site_choice

        link_view_mode = st.radio(
            "Links to show",
            ["All links", "Physical only", "Logical only"],
            help=(
                "Based on link_type field in YAML. "
                "Physical: cables, ports, etc. Logical: tunnels, subinterfaces, SVIs."
            ),
        )

        with st.expander("Legend", expanded=False):
            st.markdown(
                """
                **Node colors**

                - Routers: green
                - Switches: blue
                - Firewalls: orange
                - Servers/hosts: yellow/teal

                **Status (border color)**

                - Up: green border
                - Down: red border
                - Unknown: gray border
                """
            )

    node_status = evaluate_status(g, enable_ping=enable_ping, selected_site=selected_site)

    with col_summary:
        st.subheader("Summary")
        total_nodes = len(g.nodes)
        up_nodes = sum(1 for s in node_status.values() if s == "up")
        down_nodes = sum(1 for s in node_status.values() if s == "down")

        st.metric("Total nodes", total_nodes)
        st.metric("Up", up_nodes)
        st.metric("Down", down_nodes)

        # Simple role distribution chart
        roles = {}
        for _, attrs in g.nodes(data=True):
            role = attrs.get("role", "unknown") or "unknown"
            roles[role] = roles.get(role, 0) + 1
        if roles:
            df_roles = pd.DataFrame(
                {"role": list(roles.keys()), "count": list(roles.values())}
            ).set_index("role")
            st.bar_chart(df_roles)

    st.subheader("Topology")
    net = build_pyvis_network(
        g,
        node_status,
        selected_site=selected_site,
        link_view_mode=link_view_mode,
    )

    # Generate HTML and embed in Streamlit
    html_path = BASE_DIR / "_tmp_topology.html"
    # Use write_html instead of show() to avoid notebook-specific render issues
    net.write_html(str(html_path))
    html_content = html_path.read_text(encoding="utf-8")
    components.html(html_content, height=700, scrolling=True)

    st.subheader("Raw Topology Data")
    st.json(data)


def render_ccna_study_page():
    st.title("CCNA Study Guide & Glossary")

    topic_names = list(CCNA_TOPICS.keys())
    topic_name = st.selectbox("Choose a topic", topic_names)
    topic = CCNA_TOPICS[topic_name]

    st.subheader("Overview")
    st.write(topic.get("summary", ""))

    key_points = topic.get("key_points") or []
    if key_points:
        st.subheader("Key concepts")
        for point in key_points:
            st.markdown(f"- {point}")

    terms = topic.get("terms") or {}
    if terms:
        st.subheader("Key terms")
        for term, definition in terms.items():
            st.markdown(f"**{term}** – {definition}")

    related = topic.get("related_examples") or []
    if related:
        st.subheader("Related example topologies")
        st.markdown(
            "These concepts appear in example or random labs with names like:" "<br>" + "<br>".join(f"• {name}" for name in related),
            unsafe_allow_html=True,
        )


def main():
    st.set_page_config(page_title="Network Topology Viewer", layout="wide")

    with st.sidebar:
        st.header("Navigation")
        page = st.radio("Page", ["Topology Viewer", "CCNA Study Guide"])

    if page == "Topology Viewer":
        render_topology_page()
    else:
        render_ccna_study_page()


if __name__ == "__main__":
    main()
