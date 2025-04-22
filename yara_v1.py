import re
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score

def extract_yara_rules(yara_text):
    rules = []
    current_rule = ""
    inside_rule = False
    brace_count = 0

    for line in yara_text:
        stripped = line.strip()

        if stripped.startswith("rule "):
            inside_rule = True
            current_rule = line
            brace_count = line.count("{") - line.count("}")

        elif inside_rule:
            current_rule += line
            brace_count += line.count("{") - line.count("}")

            if brace_count == 0:
                rules.append(current_rule)
                inside_rule = False
                current_rule = ""
    
    rules_data = []  
    for rule_text in rules:
        rule_data = {}

        # Get rule body
        body_match = re.search(r'\{(.*)\}', rule_text, re.DOTALL)
        rule_body = body_match.group(1) if body_match else ""

        # Get rule name
        name_match = re.search(r'rule\s+(\w+)', rule_text)
        rule_data['rule_name'] = name_match.group(1) if name_match else "Unknown"

        if "_" in rule_data['rule_name']:
            parts = rule_data['rule_name'].split("_")
        
            # Remove parts 
            cleaned_parts = [
                part for part in parts 
                if not re.search(r'(apt|malware|apt1|apr17)', part, re.IGNORECASE)
            ]
            
            # Reconstruct the rule name
            rule_data['rule_name'] = "_".join(cleaned_parts)
        else:
            rule_data['rule_name'] 

        # Check if rule_name ends with or contains a long hex string
        if re.search(r'[a-fA-F0-9]{16,}', rule_data['rule_name']):
            meta_match = re.search(
                r'meta:\s*(.*?)(?=\bstrings:|\bcondition:|\})', rule_body, re.DOTALL | re.IGNORECASE
            )
            if meta_match:
                meta_block = meta_match.group(1)
                desc_match = re.search(r'description\s*=\s*"([^"]+)"', meta_block)
                if desc_match:
                    rule_data['rule_name'] = desc_match.group(1).strip()
                else:
                    rule_data['rule_name']
            else:
                rule_data['rule_name']


        

        # === STRINGS ===
        strings_match = re.search(r'strings:\s*(.*?)(?=^\s*(meta:|condition:|\}))', rule_body, re.DOTALL | re.IGNORECASE | re.MULTILINE)
        string_lines = []
        hex_patterns = []

        if strings_match:
            strings_block = strings_match.group(1)

            # Regex patterns
            regex_patterns = re.findall(r'/([^/]+)/', strings_block)
            if regex_patterns:
                string_lines.extend(regex_patterns)

            # Plain text strings
            text_strings = re.findall(r'"(.*?)"', strings_block)
            string_lines.extend(text_strings)

            # Hex patterns
            hex_patterns = re.findall(r'\{([^}]+)\}', strings_block)

        rule_data['string_lines'] = string_lines
        rule_data['hex_patterns'] = hex_patterns

        # === CONDITION ===
        condition_match = re.search(r'condition:\s*(.*)', rule_body, re.DOTALL | re.IGNORECASE)
        condition_block = condition_match.group(1).strip() if condition_match else ""
        rule_data['condition'] = condition_block

        # Extract filesize expressions
        # filesize_matches = re.findall(r'filesize\s*([<>=!]+)\s*([^\s\)]+)', condition_block)
        filesize_matches = re.findall(r'filesize\s*(==|!=|<=|>=|<|>)\s*([0-9]+(?:\.[0-9]+)?\s*(?:[kKmMgGtTpP][bB])?)', condition_block)

        rule_data['filesize_conditions'] = filesize_matches
#         pattern = r'filesize\s*(==|!=|<=|>=|<|>)\s*([0-9]+(?:\.[0-9]+)?\s*(?:[kKmMgGtTpP][bB])?)'
#         matches = re.findall(pattern, condition)
#         for op, value in matches:
#             filesize.append(op + value.strip())

        rules_data.append(rule_data)
        
    return rules_data

def parse_yara_rule(file_path):
    """
    Extracts features from a YARA rule file.
    
    Parameters:
        file_path (str): Path to the YARA rule file.
    
    Returns:
        list: A list of numerical features extracted from the YARA rule.
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        # yara_rule = f.read()
        yara_rule = f.readlines()

    
    # Extract strings, hex patterns, and conditions from the YARA rule
    rules_data = extract_yara_rules(yara_rule)

    # Count extracted features
    featured_rules = []

    for rule in rules_data:
        condition_raw = rule['condition']
        string_lines = rule['string_lines']
        hex_patterns = rule['hex_patterns']
        filesize = rule['filesize_conditions']


        # Split condition into parts (approximate logic statements)
        condition_elements = re.split(r'\band\b|\bor\b|\band\s+not\b|==|!=|>=|<=|<|>|[\n\r]', condition_raw)
        condition_elements = [c.strip() for c in condition_elements if c.strip()]
        num_conditions = len(condition_elements)


        # Check if the rule contains execution-related keywords
        contains_exec = 1 if any(cmd in yara_rule for cmd in ["bash", "exec", "cmd.exe"]) else 0

        # Get mean
        total_rules = len(rules_data)
        total_strings = sum(len(string_lines)for rule in rules_data)
        total_conditions = sum(num_conditions for rule in rules_data)
        total_hexpatterns = sum(len(hex_patterns) for rule in rules_data)     

        avg_strings = total_strings / total_rules if total_rules else 0
        avg_conditions = total_conditions / total_rules if total_rules else 0
        avg_hex = total_hexpatterns / total_rules if total_rules else 0

        file_name = os.path.basename(file_path)
        file_base_name = os.path.splitext(file_name)[0]


        if "_" in file_base_name:
            parts = file_base_name.split("_")
        
            # Remove parts 
            cleaned_parts = [
                part for part in parts 
                if not re.search(r'(apt|malw|apt1)', part, re.IGNORECASE)
            ]
            
            # Reconstruct the rule name
            file_base_name = "_".join(cleaned_parts)
        else:
            file_base_name 
   
        
        featured_rules.append({
            
            "malware_name": rule["rule_name"],
            "strings": string_lines,
            "conditions": condition_raw,
            "hex_patterns":hex_patterns,
            # "num_strings": len(string_lines),
            # "num_conditions": num_conditions,
            # "num_hex_patterns": len(hex_patterns),
            "rule_length": len(yara_rule),
            "file_size": filesize,
            "contains_exec":contains_exec,
            # "avg_strings": avg_strings,
            # "avg_conditions": avg_conditions,
            # "avg_hex_patterns": avg_hex,
            "family": file_base_name,
        })

    return featured_rules


# parse_yara_rule("C:/Users/stouk/Desktop/YARA/Yara/MALW_Ponmocup.yar")

def load_yara_rules(directory):
    """
    Loads YARA rules from a directory and extracts features from each rule.
    
    Parameters:
        directory (str): Path to the directory containing YARA rule files.
    
    Returns:
        tuple: A NumPy array of extracted features and a list of corresponding labels.
    """
    features = []
    labels = []
    
    # Iterate through all files in the directory
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                file_path = os.path.join(root, file)

                parsed_rules = parse_yara_rule(file_path)
                for rule in parsed_rules:
                    features.append(rule)
                    labels.append("malware")

                # features.append(parse_yara_rule(file_path))
                # features = parse_yara_rule(file_path)
                # labels.append("malware")  # Assuming all rules in the repo are for malware detection
    
    return features, labels
    # return np.array(features), labels

# Load YARA rules from GitHub repo directory
yara_repo_path = "C:/Users/stouk/Desktop/YARA/rules"  # Update with local path after cloning
X, labels = load_yara_rules(yara_repo_path)


# Data Pre-processing
# Encode labels using LabelEncoder\label_encoder = LabelEncoder()
family = []
le = LabelEncoder()
y_encoded = le.fit_transform(labels)
for rule in X:
    family.append(rule['family'])
    y2_encoded = le.fit_transform(family)


# Upload data to csv file
df = pd.DataFrame(X)
df["class"] = y2_encoded
df["label"] = y_encoded
df.to_csv("yara_features.csv", index=False)





# # Split dataset into training and testing sets
# X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

# # Train a Random Forest model for classification
# model = RandomForestClassifier(n_estimators=100, random_state=42)
# model.fit(X_train, y_train)

# # Test the model and calculate accuracy
# predictions = model.predict(X_test)
# accuracy = accuracy_score(y_test, predictions)
# print(f"Model Accuracy: {accuracy * 100:.2f}%")



