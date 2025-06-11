import json
import csv
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

def extract_detections(data):
    """Extract specified fields from detection JSON."""
    extracted_data = []
    
    for detection in data:
        
        detection_info = {
            'Hostname': detection.get('device', {}).get('hostname', ''),
            'OS_Version': detection.get('device', {}).get('os_version', ''),
            'Severity': detection.get('severity_name', ''),
            'Confidence': detection.get('confidence', ''),
            'Tactic': detection.get('tactic', ''),
            'Technique': detection.get('technique', ''),
            'Description': detection.get('description', ''),
            'Process_Name': detection.get('filename', ''),
            'Process_Path': detection.get('filepath', ''),
            'Command_Line': detection.get('cmdline', ''),
            'User_Name': detection.get('user_name', ''),
            'Parent_Process': detection.get('parent_details', {}).get('filename', ''),
            'Parent_Command_Line': detection.get('parent_details', {}).get('cmdline', ''),
            'SHA256': detection.get('sha256', ''),
            'MD5': detection.get('md5', '')
        }
        
        
        files_accessed = detection.get('files_accessed', [])
        files_written = detection.get('files_written', [])
        detection_info['Files_Accessed'] = ';'.join([f"{f['filename']} ({f['filepath']})" for f in files_accessed])
        detection_info['Files_Written'] = ';'.join([f"{f['filename']} ({f['filepath']})" for f in files_written])
        
       
        ioc_context = detection.get('ioc_context', [])
        ioc_values = [ioc.get('ioc_value', '') for ioc in ioc_context]
        detection_info['IOCs'] = ';'.join(ioc_values)
        
        
        network_accesses = detection.get('network_accesses', [])
        network_info = [f"{n['remote_address']}:{n['remote_port']} ({n['protocol']})" for n in network_accesses]
        detection_info['Network_Accesses'] = ';'.join(network_info)
        
        extracted_data.append(detection_info)
    
    return extracted_data

def save_to_csv(data, output_file):
    """Save extracted data to CSV file."""
    if not data:
        print("No data to save.")
        return
    
    fieldnames = [
        'Hostname', 'OS_Version', 'Severity', 'Confidence', 'Tactic', 'Technique', 'Description',
        'Process_Name', 'Process_Path', 'Command_Line', 'User_Name', 'Parent_Process',
        'Parent_Command_Line', 'Files_Accessed', 'Files_Written', 'IOCs', 'Network_Accesses',
        'SHA256', 'MD5'
    ]
    
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"Data successfully saved to {output_file}")
    except IOError as e:
        print(f"Error writing to {output_file}: {e}")

def main():
    
    input_file = 'Detection-3.json'  
    
    output_file = f'edr_detections_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    
    data = load_json_file(input_file)
    if not data:
        return
    
   
    extracted_data = extract_detections(data)
    
    
    save_to_csv(extracted_data, output_file)

if __name__ == '__main__':
    main()