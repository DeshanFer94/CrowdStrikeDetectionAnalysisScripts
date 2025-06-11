import json
from collections import Counter
from datetime import datetime
from pathlib import Path

def load_json_file(file_path):
    """Load JSON file and return parsed data."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return None
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in {file_path}.")
        return None

def count_detections(data):
    """Count occurrences of tactics, techniques, hosts, processes, and IOCs."""
    tactics = Counter()
    techniques = Counter()
    hosts = Counter()
    processes = Counter()
    ioc_count = 0

    for detection in data:
        # Count tactics
        tactic = detection.get('tactic', 'Unknown')
        tactics[tactic] += 1

        # Count techniques
        technique = detection.get('technique', 'Unknown')
        techniques[technique] += 1

        # Count hosts
        hostname = detection.get('device', {}).get('hostname', 'Unknown')
        hosts[hostname] += 1

        # Count processes
        process_name = detection.get('filename', 'Unknown')
        processes[process_name] += 1

        # Count IOCs (non-empty ioc_value in ioc_context)
        ioc_context = detection.get('ioc_context', [])
        for ioc in ioc_context:
            if ioc.get('ioc_value', ''):
                ioc_count += 1

    return tactics, techniques, hosts, processes, ioc_count

def count_os_versions(data):
    """Count occurrences of OS versions and calculate total detections."""
    os_versions = Counter()
    total_detections = len(data)

    for detection in data:
        # Count OS versions
        os_version = detection.get('device', {}).get('os_version', 'Unknown')
        os_versions[os_version] += 1

    return os_versions, total_detections

def save_counts_to_file(tactics, techniques, hosts, processes, ioc_count, os_versions, total_detections, output_file):
    """Save counts to a text file in the specified format."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            
            f.write("====Occurrence of Tactics Defense====\n")
            for tactic, count in sorted(tactics.items()):
                f.write(f"{tactic}: {count}\n")
            f.write("\n")
           
            f.write("====Occurrence of Techniques====\n")
            for technique, count in sorted(techniques.items()):
                f.write(f"{technique}: {count}\n")
            f.write("\n")
            
            f.write("====Host Detection Counts====\n")
            for host, count in sorted(hosts.items()):
                f.write(f"{host}: {count}\n")
            f.write("\n")
           
            f.write("====Process Occurrence====\n")
            for process, count in sorted(processes.items()):
                f.write(f"{process}: {count}\n")
            f.write("\n")
            
            f.write(f"Number of IOC Extracted IOC: {ioc_count}\n")

            f.write("====Occurrence of OS Versions====\n")
            for os_version, count in sorted(os_versions.items()):
                f.write(f"{os_version}: {count}\n")
            f.write("\n")

            # Write Percentage of OS Versions
            f.write("====Percentage of OS Versions====\n")
            for os_version, count in sorted(os_versions.items()):
                percentage = (count / total_detections) * 100 if total_detections > 0 else 0
                f.write(f"{os_version}: {percentage:.1f}%\n")

        print(f"Counts successfully saved to {output_file}")
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")

def main():
    # Input JSON file path
    input_file = 'Detection-3.json' 
    # Output text file path
    output_file = f'edr_detection_counts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
    
    # Load JSON data
    data = load_json_file(input_file)
    if not data:
        return
    
    # Count detections
    tactics, techniques, hosts, processes, ioc_count = count_detections(data)
    
    # Count OS versions and total detections
    os_versions, total_detections = count_os_versions(data)
    
    # Save counts to file
    save_counts_to_file(tactics, techniques, hosts, processes, ioc_count, os_versions, total_detections, output_file)

if __name__ == '__main__':
    main()