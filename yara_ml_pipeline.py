import re
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score

def parse_yara_rule(file_path):
    """
    Extracts features from a YARA rule file.
    
    Parameters:
        file_path (str): Path to the YARA rule file.
    
    Returns:
        list: A list of numerical features extracted from the YARA rule.
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        yara_rule = f.read()
    
    # Extract strings, hex patterns, and conditions from the YARA rule

    #check if you can get it from Identifier or rule
    rule_match = re.search(r'\brule\s+(\w+)', yara_rule)
    category = rule_match.group(1) if rule_match else "unknown_category"


    strings = re.findall(r'"(.*?)"', yara_rule)
    hex_patterns = re.findall(r'\{(.*?)\}', yara_rule)
    conditions = re.findall(r'\b(any|all|them)\b', yara_rule)

    print('category',category)
    print('strings', strings)
    print('hexpatterns', hex_patterns)
    print('conditions', conditions)

    
    # Count extracted features
    num_strings = len(strings)
    num_hex_patterns = len(hex_patterns)
    num_conditions = len(conditions)
    rule_length = len(yara_rule)

    #get mean, avg...
    #
    # 

    # Check if the rule contains execution-related keywords
    contains_exec = 1 if any(cmd in yara_rule for cmd in ["bash", "exec", "cmd.exe"]) else 0
    
    return [category,num_strings, num_hex_patterns, num_conditions, rule_length, contains_exec]

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
                features.append(parse_yara_rule(file_path))
                labels.append("malware")  # Assuming all rules in the repo are for malware detection
    
    return np.array(features), labels

# Load YARA rules from GitHub repo directory
yara_repo_path = "./signature-base/yara"  # Update with local path after cloning
# X, labels = load_yara_rules(yara_repo_path)

ex = parse_yara_rule('./RANSOM_Pico.yar')

# Encode labels using LabelEncoder\label_encoder = LabelEncoder()
# y_encoded = label_encoder.fit_transform(labels)
# y_encoded = LabelEncoder.fit_transform(labels)





# # Split dataset into training and testing sets
# X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

# # Train a Random Forest model for classification
# model = RandomForestClassifier(n_estimators=100, random_state=42)
# model.fit(X_train, y_train)

# # Test the model and calculate accuracy
# predictions = model.predict(X_test)
# accuracy = accuracy_score(y_test, predictions)
# print(f"Model Accuracy: {accuracy * 100:.2f}%")
