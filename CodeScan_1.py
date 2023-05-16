import os
import re
from pybloom_live import BloomFilter

def scan_code_for_vulnerabilities(directory):
    # Define known vulnerable patterns or signatures
    vulnerable_patterns = [
        r"pickle\.loads",
        r"os\.system",
        r"subprocess\.Popen",
        # Add more vulnerable patterns as needed
    ]

    # Create a Bloom filter and add vulnerable patterns to it
    bloom_filter = BloomFilter(capacity=1000, error_rate=0.1)
    for pattern in vulnerable_patterns:
        bloom_filter.add(pattern)

    # Iterate through Python files in the given directory
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            if file_name.endswith(".py"):
                file_path = os.path.join(root, file_name)
                with open(file_path, "r") as file:
                    code = file.read()
                    vulnerabilities = []
                    # Scan the code for vulnerable patterns
                    for pattern in bloom_filter:
                        if re.search(pattern, code):
                            vulnerabilities.append(pattern)
                    if vulnerabilities:
                        print(f"Potential vulnerabilities found in: {file_path}")
                        for vulnerability in vulnerabilities:
                            print(f"- {vulnerability}")

# Specify the directory to scan
directory_to_scan = "path/to/directory"

# Scan the Python code for vulnerabilities
scan_code_for_vulnerabilities(directory_to_scan)
