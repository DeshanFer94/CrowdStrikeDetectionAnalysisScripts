# CrowdStrikeDetectionAnalysisScripts
This includes Python scripts designed to extract, analyze, and export detection data from CrowdStrike EDR JSON exports. It provides actionable insights in CSV and TXT formats to support incident response, threat analysis, and SOC reporting workflows.


# CrowdStrike Detection Data Extractor and Analyzer
This project includes two Python scripts that process and analyze detection data exported from CrowdStrike EDR. The tools help Security Analysts and Incident Responders extract meaningful insights from raw detection JSON files and convert them into structured CSV and summarized TXT reports.

## Features

- Extracts detailed detection attributes such as hostname, process details, command line, file accesses, network connections, and hashes.
- Summarizes key statistics: tactic/technique frequency, host activity, OS distribution, and IOC counts.
- Outputs:
  - CSV file with extracted detection fields
  - TXT summary file with counts and percentages

## Scripts

### 1. `CS_Analysis_to_Excel.py`

- Loads detection JSON file (`Detection-3.json`)
- Extracts:
  - Host, OS, severity, confidence, tactic, technique, command line, parent/child process, IOCs, files, and network activity
- Outputs:
  - `edr_detections_<timestamp>.csv`

### 2. `CS_Analysis-Data_Extraction.py`

- Loads the same JSON file
- Performs statistical analysis:
  - Counts of tactics, techniques, hosts, processes, IOCs, and OS versions
  - Percentages of OS versions
- Outputs:
  - `edr_detection_counts_<timestamp>.txt`

## Usage

```bash
python CS_Analysis_to_Excel.py
python CS_Analysis-Data_Extraction.py

## Dependencies 
Python 3.x
Standard libraries: json, csv, datetime, collections, pathlib


