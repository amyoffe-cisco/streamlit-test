# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Detection Rules Viewer - Streamlit app to visualize detection rules and
their MITRE ATT&CK techniques.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Union
from urllib.parse import urlparse
from urllib.request import urlopen

# Add project root to Python path to access mitre_mapping module
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import altair as alt
import pandas as pd
import streamlit as st
from mitre_mapping.mitre_attack_mapper import SubTechnique, Technique, get_mapper


def sort_tactics(tactics_to_sort: Union[List[str], set]) -> List[str]:
    """
    Filter and sort tactics based on canonical MITRE ATT&CK Enterprise order.

    Args:
        tactics_to_sort: Tactic names to sort

    Returns:
        List of tactics sorted by canonical order, containing only tactics
        that are present in the input
    """
    # Canonical MITRE ATT&CK Enterprise tactic order.
    # Reference: https://attack.mitre.org/tactics/enterprise/
    CANONICAL_TACTIC_ORDER = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    ]

    return [tactic for tactic in CANONICAL_TACTIC_ORDER if tactic in tactics_to_sort]


st.set_page_config(layout="wide")

st.title("Detection Rules Viewer")


# Load JSON data
@st.cache_data
def load_detection_rules(classified_output_file: str) -> pd.DataFrame:
    """
    Load detection rules from a JSON file or URL.

    Args:
        classified_output_file: Path to local file or HTTP/HTTPS URL

    Returns:
        DataFrame containing the detection rules
    """
    # Check if the input is a URL
    parsed_url = urlparse(classified_output_file)
    is_url = parsed_url.scheme in ("http", "https")

    if is_url:
        # Load from URL
        with urlopen(classified_output_file) as response:
            data = json.loads(response.read().decode("utf-8"))
    else:
        # Load from local file
        with open(classified_output_file, "r", encoding="utf-8") as f:
            data = json.load(f)

    rules_df = pd.DataFrame(data)
    rules_df = rules_df.rename(
        columns={"id": "rule_id", "relevant_techniques": "technique_ids"}
    )

    return rules_df


def enrich_technique_data(row: pd.Series) -> pd.Series:
    """
    Enrich a row with technique/subtechnique data from MITRE ATT&CK.

    This adds:
    - ts_or_st_pretty: Pretty formatted technique or subtechnique string
    - tactics: List of tactic objects associated with this technique
    """
    mapper = get_mapper()
    technique_id = row["technique_id"]

    if not technique_id:
        row["ts_or_st_pretty"] = None
        row["tactics"] = []
        return row

    if "." in technique_id:
        # It's a sub-technique
        sub_tech = mapper.get_sub_technique(technique_id)
        if sub_tech:
            # Format: "[T1098.001] Account Manipulation > Additional Cloud Credentials"
            row["ts_or_st_pretty"] = (
                f"[{sub_tech.id}] {sub_tech.technique.name} > {sub_tech.name}"
            )
            # Get tactics from parent technique
            row["tactics"] = sub_tech.technique.tactics
        else:
            row["ts_or_st_pretty"] = None
            row["tactics"] = []
    else:
        # It's a technique
        tech = mapper.get_technique(technique_id)
        if tech:
            # Format: "[T1234] Foo"
            row["ts_or_st_pretty"] = f"[{tech.id}] {tech.name}"
            row["tactics"] = tech.tactics
        else:
            row["ts_or_st_pretty"] = None
            row["tactics"] = []

    return row


def enrich_tactic_data(row: pd.Series) -> pd.Series:
    """
    Enrich a row with tactic data.

    This adds:
    - tactic_id: Tactic ID (e.g., TA0005)
    - tactic_pretty: Pretty formatted tactic string
    - kill_chain_stages: List of kill chain stage objects for this tactic
    """
    tactic = row["tactic"]

    # Check if tactic is not NaN/None and has the expected attributes
    if tactic is not None and not pd.isna(tactic) and hasattr(tactic, "id"):
        row["tactic_id"] = tactic.id
        row["tactic_pretty"] = f"[{tactic.id}] {tactic.name}"
        row["kill_chain_stages"] = tactic.kill_chain_stages
    else:
        row["tactic_id"] = None
        row["tactic_pretty"] = None
        row["kill_chain_stages"] = []

    return row


def enrich_kill_chain_data(row: pd.Series) -> pd.Series:
    """
    Enrich a row with kill chain stage data.

    This adds:
    - kill_chain_id: Kill chain step number
    - kill_chain_pretty: Pretty formatted kill chain string
    """
    kc_stage = row["kill_chain_stage"]

    # Check if kc_stage is not NaN/None and has the expected attributes
    if (
        kc_stage is not None
        and not pd.isna(kc_stage)
        and hasattr(kc_stage, "kill_chain_step_number")
    ):
        row["kill_chain_id"] = kc_stage.kill_chain_step_number
        row["kill_chain_pretty"] = (
            f"[{kc_stage.kill_chain_step_number}] {kc_stage.name}"
        )
    else:
        row["kill_chain_id"] = None
        row["kill_chain_pretty"] = None

    return row


# Function to parse arguments
def parse_args(argv: List[str]) -> argparse.Namespace:
    """Parse arguments."""
    parser = argparse.ArgumentParser(description="Detection Rules Viewer")
    parser.add_argument(
        "--classified-output-file-path",
        default="output/classification/classified_output.json",
        help=(
            "Path to classified output file or URL "
            "(default: output/classification/classified_output.json)"
        ),
    )
    return parser.parse_args(argv)


try:
    args = parse_args(sys.argv[1:])
except SystemExit:
    # This exception is raised if --help or invalid arguments are used.
    # Streamlit prevents the program from exiting normally, so we handle it.
    st.error("Error parsing arguments. Check terminal for help message.")
    st.stop()  # Stop the app if arguments are invalid or help is requested


# Load the data - each row is a rule with a list of technique IDs
# Use secrets if available, otherwise fall back to command line argument
classified_output_path = args.classified_output_file_path
if "classified_output_file_path" in st.secrets:
    classified_output_path = st.secrets["classified_output_file_path"]

input_rule_classfication_df = load_detection_rules(classified_output_path)
input_rule_classfication_df = input_rule_classfication_df.sort_values("rule_id")

# Enrich the data with full MITRE ATT&CK metadata

# Step 1: Explode technique_ids to get one row per (rule_id, technique_id)
rule_techniques_df = input_rule_classfication_df.explode("technique_ids").rename(
    columns={"technique_ids": "technique_id"}
)
# Enrich with technique-level data (ts_or_st_pretty, tactics list)
rule_techniques_df = rule_techniques_df.apply(enrich_technique_data, axis=1)

# Step 2: Explode tactics to get one row per (rule_id, technique_id, tactic_id)
rule_tactics_df = (
    rule_techniques_df.explode("tactics").rename(columns={"tactics": "tactic"}).copy()
)
# Enrich with tactic-level data (tactic_id, tactic_pretty, kill_chain_stages list)
rule_tactics_df = rule_tactics_df.apply(enrich_tactic_data, axis=1)

# Step 3: Explode kill_chain_stages to get one row per (rule_id, technique_id, tactic_id, kill_chain_id)
rule_kill_chains_df = (
    rule_tactics_df.explode("kill_chain_stages")
    .rename(columns={"kill_chain_stages": "kill_chain_stage"})
    .copy()
)
# Enrich with kill_chain-level data (kill_chain_id, kill_chain_pretty)
rule_kill_chains_df = rule_kill_chains_df.apply(enrich_kill_chain_data, axis=1)

# Create pretty-formatted versions of the dataframes, on all aggregation levels.

rule_tactics_pretty_df = (
    rule_kill_chains_df.groupby(["rule_id", "technique_id", "tactic_id"])
    .agg(
        {
            "ts_or_st_pretty": "first",
            "tactic_pretty": "first",
            "kill_chain_pretty": lambda x: tuple(
                sorted(set(x))
            ),  # Ordered unique values
        }
    )
    .reset_index()
    .rename(
        columns={
            "ts_or_st_pretty": "technique",
            "tactic_pretty": "tactic",
            "kill_chain_pretty": "kill_chain",
        }
    )
)

rule_techniques_pretty_df = (
    rule_tactics_pretty_df.groupby(["rule_id", "technique_id"])
    .agg(
        {
            "technique": "first",
            "tactic": lambda x: tuple(sorted(set(x))),  # Ordered unique values
            "kill_chain": lambda x: tuple(
                sorted(set(item for tup in x for item in tup))
            ),  # Flatten tuples and get unique values
        }
    )
    .reset_index()
)

rules_pretty_df = (
    rule_techniques_pretty_df.groupby("rule_id")
    .agg(
        {
            "technique": lambda x: tuple(sorted(set(x))),  # Ordered unique values
            "tactic": lambda x: tuple(
                sorted(set(item for tup in x for item in tup))
            ),  # Flatten tuples and get unique values
            "kill_chain": lambda x: tuple(
                sorted(set(item for tup in x for item in tup))
            ),  # Flatten tuples and get unique values
        }
    )
    .reset_index()
)

# For backwards compatibility with downstream code, create rules_df by aggregating rule_techniques_df
# TODO: Update downstream code to use the new granular dataframes
rules_df = (
    rule_techniques_df.groupby("rule_id")
    .agg(
        {
            "technique_id": list,
            "ts_or_st_pretty": list,
        }
    )
    .reset_index()
    .rename(
        columns={
            "technique_id": "technique_ids",
            "ts_or_st_pretty": "ts_or_sts_pretty",
        }
    )
)

# Display the data
st.write(f"Showing {len(rules_df)} detection rules")

# Create Tactic Coverage chart - Horizontal Stacked by Technique
st.subheader("Tactic Coverage")

# Use rule_tactics_df which already has tactic_pretty and ts_or_st_pretty
tactic_technique_df = rule_tactics_df.copy()

# Count rule mappings for each tactic-technique pair
tactic_technique_counts = (
    tactic_technique_df.groupby(["tactic_pretty", "ts_or_st_pretty"])
    .size()
    .reset_index(name="rule_mappings")
)

# Extract tactic name only (remove the ID prefix like "[TA0003] ")
tactic_technique_counts["tactic_name"] = tactic_technique_counts[
    "tactic_pretty"
].str.replace(r"^\[.*?\]\s*", "", regex=True)

# Sort by canonical MITRE ATT&CK tactic order for chart consistency
tactics_present = tactic_technique_counts["tactic_name"].unique()
tactic_order = sort_tactics(tactics_present)

# Create the horizontal stacked bar chart
tactic_chart = (
    alt.Chart(tactic_technique_counts)
    .mark_bar()
    .encode(
        x=alt.X(
            "sum(rule_mappings):Q",
            title="Total rule mappings",
            axis=alt.Axis(
                format="d",  # Format as integer (no decimals)
            ),
        ),
        y=alt.Y(
            "tactic_name:N",
            title="Tactic",
            sort=tactic_order,
            axis=alt.Axis(labelLimit=200),
        ),
        color=alt.Color(
            "ts_or_st_pretty:N",
            title="Technique",
            legend=None,  # Hide legend as there are too many techniques
        ),
        tooltip=[
            alt.Tooltip("tactic_name:N", title="Tactic"),
            alt.Tooltip("ts_or_st_pretty:N", title="Technique"),
            alt.Tooltip("rule_mappings:Q", title="Rule mappings"),
        ],
    )
    .properties(height=400)
)

st.altair_chart(tactic_chart, use_container_width=True)

# Create Kill Chain Coverage chart - Horizontal Stacked by Technique
st.subheader("Kill Chain Coverage")

# Use rule_kill_chains_df which already has kill_chain_pretty and ts_or_st_pretty
kill_chain_technique_df = rule_kill_chains_df.copy()

# Count rule mappings for each kill_chain-technique pair
kill_chain_technique_counts = (
    kill_chain_technique_df.groupby(["kill_chain_pretty", "ts_or_st_pretty"])
    .size()
    .reset_index(name="rule_mappings")
)

# Extract kill chain name and step number for sorting
kill_chain_technique_counts["kill_chain_name"] = kill_chain_technique_counts[
    "kill_chain_pretty"
].str.replace(r"^\[.*?\]\s*", "", regex=True)

# Get kill chain step numbers for proper ordering
kill_chain_with_step = (
    kill_chain_technique_df[["kill_chain_pretty", "kill_chain_id"]]
    .drop_duplicates()
    .set_index("kill_chain_pretty")["kill_chain_id"]
    .to_dict()
)

# Add step numbers to counts dataframe and sort
kill_chain_technique_counts["kill_chain_step"] = kill_chain_technique_counts[
    "kill_chain_pretty"
].map(kill_chain_with_step)

# Sort by kill chain step number
kill_chain_order = (
    kill_chain_technique_counts[["kill_chain_pretty", "kill_chain_step"]]
    .drop_duplicates()
    .sort_values("kill_chain_step")["kill_chain_pretty"]
    .tolist()
)

# Create the horizontal stacked bar chart
kill_chain_chart = (
    alt.Chart(kill_chain_technique_counts)
    .mark_bar()
    .encode(
        x=alt.X(
            "sum(rule_mappings):Q",
            title="Total rule mappings",
            axis=alt.Axis(
                format="d",  # Format as integer (no decimals)
            ),
        ),
        y=alt.Y(
            "kill_chain_pretty:N",
            title="Kill Chain Stage",
            sort=kill_chain_order,
            axis=alt.Axis(labelLimit=200),
        ),
        color=alt.Color(
            "ts_or_st_pretty:N",
            title="Technique",
            legend=None,  # Hide legend as there are too many techniques
        ),
        tooltip=[
            alt.Tooltip("kill_chain_pretty:N", title="Kill Chain Stage"),
            alt.Tooltip("ts_or_st_pretty:N", title="Technique"),
            alt.Tooltip("rule_mappings:Q", title="Rule mappings"),
        ],
    )
    .properties(height=400)
)

st.altair_chart(kill_chain_chart, use_container_width=True)

# Create Tactic vs Kill-Chain Heatmap
st.subheader("Tactic / Kill-Chain Coverage")

# Use rule_kill_chains_df which already has all the data we need
tactic_kc_df = rule_kill_chains_df.copy()

# Extract tactic names and kill-chain names from the pretty formatted strings
tactic_kc_df["tactic_name"] = tactic_kc_df["tactic_pretty"].str.replace(
    r"^\[.*?\]\s*", "", regex=True
)
tactic_kc_df["kill_chain_name"] = tactic_kc_df["kill_chain_pretty"]
tactic_kc_df["kill_chain_step_num"] = tactic_kc_df["kill_chain_id"]

# Count unique rules for each tactic-killchain pair
tactic_kc_counts = (
    tactic_kc_df.groupby(["tactic_name", "kill_chain_name", "kill_chain_step_num"])
    .agg({"rule_id": "nunique"})
    .reset_index()
    .rename(columns={"rule_id": "rule_count"})
)

# Get the tactics present in the data and sort them by canonical order
present_tactics = set(tactic_kc_counts["tactic_name"].unique())
tactic_sort_order = sort_tactics(present_tactics)

# Sort kill-chain by step number (ascending)
kc_sort_order = (
    tactic_kc_counts[["kill_chain_name", "kill_chain_step_num"]]
    .drop_duplicates()
    .sort_values("kill_chain_step_num")["kill_chain_name"]
    .tolist()
)

# Create heatmap
heatmap = (
    alt.Chart(tactic_kc_counts)
    .mark_rect()
    .encode(
        x=alt.X(
            "kill_chain_name:N",
            title="Kill-Chain Step",
            sort=kc_sort_order,
            axis=alt.Axis(labelAngle=-45, labelLimit=200),
        ),
        y=alt.Y(
            "tactic_name:N",
            title="Tactic",
            sort=tactic_sort_order,
            scale=alt.Scale(
                domain=tactic_sort_order
            ),  # Force all tactics to appear on axis
            axis=alt.Axis(labelLimit=300, labelOverlap=False),
        ),
        color=alt.Color(
            "rule_count:Q",
            title="Number of Rules",
            scale=alt.Scale(scheme="greens"),
        ),
        tooltip=[
            alt.Tooltip("tactic_name:N", title="Tactic"),
            alt.Tooltip("kill_chain_name:N", title="Kill-Chain Step"),
            alt.Tooltip("rule_count:Q", title="Number of Rules"),
        ],
    )
    .properties(height=600, width=800)
)

st.altair_chart(heatmap, use_container_width=True)

# Display dataframe of all rules with aggregated tactics and kill chains
rules_display_df = (
    rule_kill_chains_df.groupby("rule_id")
    .agg(
        {
            "ts_or_st_pretty": lambda x: list(set(x)),  # Unique techniques
            "tactic_pretty": lambda x: list(set(x)),  # Unique tactics
            "kill_chain_pretty": lambda x: list(set(x)),  # Unique kill chains
        }
    )
    .reset_index()
)

st.dataframe(rules_pretty_df)

# Create bar chart of top 20 techniques
st.subheader("Top 20 Techniques by Rule Count")

# Count unique rules for each technique
technique_counts = (
    rule_techniques_df.groupby("ts_or_st_pretty")["rule_id"]
    .nunique()
    .reset_index(name="Count")
    .rename(columns={"ts_or_st_pretty": "Technique"})
)

# Sort and get top 20
technique_df = technique_counts.sort_values("Count", ascending=False).head(20)

# Create horizontal bar chart with Altair to preserve sort order
chart = (
    alt.Chart(technique_df)
    .mark_bar()
    .encode(
        x=alt.X("Count:Q", title="Number of Rules"),
        y=alt.Y("Technique:N", sort="-x", title="", axis=alt.Axis(labelLimit=300)),
    )
    .properties(height=500)
)

st.altair_chart(chart, use_container_width=True)
