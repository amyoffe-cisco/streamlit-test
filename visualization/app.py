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
    """Load detection rules from JSON file."""
    with open(classified_output_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    rules_df = pd.DataFrame(data)
    rules_df = rules_df.rename(
        columns={"id": "rule_id", "relevant_techniques": "technique_ids"}
    )

    return rules_df


def count_techniques(df: pd.DataFrame) -> Dict[str, int]:
    """Count the frequency of each technique across all rules."""
    counts: Dict[str, int] = {}
    for techniques_list in df["ts_or_sts_pretty"]:
        for technique in techniques_list:
            counts[technique] = counts.get(technique, 0) + 1
    return counts


# Add new columns using MitreAttackMapper
def enrich_row_with_mitre_data(row: pd.Series) -> pd.Series:
    """Enrich a row with MITRE ATT&CK data from mapper."""
    mapper = get_mapper()

    # Get the technique/subtechnique ID
    t_or_st_id = row["technique_id"] if row["technique_id"] else []

    # Initialize vars for rich objects
    technique = None
    subtechnique = None
    tactics_list = []
    kill_chain_stages_list = []

    # Initialize vars for pretty formatted strings
    ts_or_st_pretty = None
    tactics_pretty = []
    kill_chain_pretty = []

    if "." in t_or_st_id:
        # It's a sub-technique
        sub_tech = mapper.get_sub_technique(t_or_st_id)
        if sub_tech:
            subtechnique = sub_tech
            # Format: "[T1098.001] Account Manipulation > Additional Cloud Credentials"
            ts_or_st_pretty = (
                f"[{sub_tech.id}] {sub_tech.technique.name} > {sub_tech.name}"
            )

            # Get tactics from parent technique
            parent_technique = sub_tech.technique
            for tactic in parent_technique.tactics:
                if tactic not in tactics_list:
                    tactics_list.append(tactic)
                    # Add kill chain stages for this tactic
                    for kc_stage in tactic.kill_chain_stages:
                        if kc_stage not in kill_chain_stages_list:
                            kill_chain_stages_list.append(kc_stage)
    else:
        # It's a technique
        tech = mapper.get_technique(t_or_st_id)
        if tech:
            technique = tech
            # Format: "[T1234] Foo"
            ts_or_st_pretty = f"[{tech.id}] {tech.name}"

            # Get tactics from technique
            for tactic in tech.tactics:
                if tactic not in tactics_list:
                    tactics_list.append(tactic)
                    # Add kill chain stages for this tactic
                    for kc_stage in tactic.kill_chain_stages:
                        if kc_stage not in kill_chain_stages_list:
                            kill_chain_stages_list.append(kc_stage)

    # Format tactics pretty strings: "[TA0005] Defense Evasion"
    tactics_pretty = [f"[{tactic.id}] {tactic.name}" for tactic in tactics_list]

    # Format kill chain pretty strings: "[3] Delivery"
    # Sort by kill_chain_step_number
    kill_chain_stages_list_sorted = sorted(
        kill_chain_stages_list, key=lambda kc: kc.kill_chain_step_number
    )
    kill_chain_pretty = [
        f"[{kc.kill_chain_step_number}] {kc.name}"
        for kc in kill_chain_stages_list_sorted
    ]

    # Add new columns to the row
    row["t_or_st_id"] = t_or_st_id
    row["technique"] = technique
    row["subtechnique"] = subtechnique
    row["tactics"] = tactics_list
    row["kill_chain_stages"] = kill_chain_stages_list_sorted
    row["ts_or_st_pretty"] = ts_or_st_pretty
    row["tactics_pretty"] = tactics_pretty
    row["kill_chain_pretty"] = kill_chain_pretty

    return row


# Function to parse arguments
def parse_args(argv: List[str]) -> argparse.Namespace:
    """Parse arguments."""
    parser = argparse.ArgumentParser(description="Detection Rules Viewer")
    parser.add_argument(
        "--classified-output-file-path",
        default="output/classification/classified_output.json",
        help=(
            "Path to classified output file "
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
input_rule_classfication_df = load_detection_rules(args.classified_output_file_path)
input_rule_classfication_df = input_rule_classfication_df.sort_values("rule_id")

# Explode multiple technique IDs into separate rows - useful for tactic/technique/kill-chain aggregations
rule_techniques_df = input_rule_classfication_df.explode("technique_ids").rename(
    columns={"technique_ids": "technique_id"}
)

# Enrich each row with MITRE ATT&CK data
rule_techniques_df = rule_techniques_df.apply(enrich_row_with_mitre_data, axis=1)

# Group by rule_id and aggregate all the rule's metadata into a single row - useful for rule-level aggregations
rules_df = (
    rule_techniques_df.groupby("rule_id")
    .agg(
        {
            "technique_id": list,
            "technique": list,
            "subtechnique": list,
            "tactics": list,
            "kill_chain_stages": list,
            "ts_or_st_pretty": list,
            "tactics_pretty": list,
            "kill_chain_pretty": list,
        }
    )
    .reset_index()
    .rename(
        columns={
            "technique_id": "technique_ids",
            "technique": "techniques",
            "subtechnique": "subtechniques",
            "ts_or_st_pretty": "ts_or_sts_pretty",
        }
    )
)

# Display the data
st.write(f"Showing {len(rules_df)} detection rules!")

# Create Tactic Coverage chart - Horizontal Stacked by Technique
st.subheader("Tactic Coverage")

# Explode tactics to get one row per rule-technique-tactic combination
tactic_technique_df = rule_techniques_df.explode("tactics_pretty")

# Count rule mappings for each tactic-technique pair
tactic_technique_counts = (
    tactic_technique_df.groupby(["tactics_pretty", "ts_or_st_pretty"])
    .size()
    .reset_index(name="rule_mappings")
)

# Extract tactic name only (remove the ID prefix like "[TA0003] ")
tactic_technique_counts["tactic_name"] = tactic_technique_counts[
    "tactics_pretty"
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

# Create Tactic vs Kill-Chain Heatmap
st.subheader("Tactic / Kill-Chain Coverage")

# Explode both tactics and kill_chain_stages to get one row per rule-tactic-killchain combination
tactic_kc_df = rule_techniques_df.explode("tactics")
tactic_kc_df = tactic_kc_df.explode("kill_chain_stages")

# Filter out rows where tactics or kill_chain_stages are None
tactic_kc_df = tactic_kc_df[
    tactic_kc_df["tactics"].notna() & tactic_kc_df["kill_chain_stages"].notna()
]

# Extract tactic names and kill-chain names
tactic_kc_df["tactic_name"] = tactic_kc_df["tactics"].apply(
    lambda t: t.name if t else None
)
tactic_kc_df["kill_chain_name"] = tactic_kc_df["kill_chain_stages"].apply(
    lambda kc: f"[{kc.kill_chain_step_number}] {kc.name}" if kc else None
)
tactic_kc_df["kill_chain_step_num"] = tactic_kc_df["kill_chain_stages"].apply(
    lambda kc: kc.kill_chain_step_number if kc else None
)

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
            axis=alt.Axis(labelLimit=200),
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
    .properties(height=400, width=800)
)

st.altair_chart(heatmap, use_container_width=True)

# Display dataframe of all rules
st.dataframe(
    rules_df[["rule_id", "ts_or_sts_pretty", "tactics_pretty", "kill_chain_pretty"]]
)

# Create bar chart of top 20 techniques
st.subheader("Top 20 Techniques by Rule Count")

# Count techniques
technique_counts = count_techniques(rules_df)

# Convert to DataFrame and sort
technique_df = pd.DataFrame(
    list(technique_counts.items()), columns=["Technique", "Count"]
)
technique_df = technique_df.sort_values("Count", ascending=False).head(20)

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
