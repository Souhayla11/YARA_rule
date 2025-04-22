import re
import os
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras import layers, models, Sequential
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier
from collections import Counter
import math
import ember
import shap
import pefile
import capstone
from sklearn.inspection import permutation_importance
from skopt import BayesSearchCV


def calculate_entropy(data):
    """Calculates Shannon entropy of a given string."""
    if not data:
        return 0
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return entropy

def parse_yara_rule(file_path):
    """Extracts features from a YARA rule file."""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        yara_rule = f.read()

    strings = re.findall(r'"(.*?)"', yara_rule)
    hex_patterns = re.findall(r'\{(.*?)\}', yara_rule)
    conditions = re.findall(r'\b(any|all|them)\b', yara_rule)

    num_strings = len(strings)
    num_hex_patterns = len(hex_patterns)
    num_conditions = len(conditions)
    rule_length = len(yara_rule)
    contains_exec = 1 if any(cmd in yara_rule for cmd in ["bash", "exec", "cmd.exe"]) else 0
    entropy = calculate_entropy(yara_rule)

    return [num_strings, num_hex_patterns, num_conditions, rule_length, contains_exec, entropy]

def build_generator(input_dim, output_dim):
    """Creates a GAN Generator model."""
    model = tf.keras.Sequential([
        layers.Dense(128, activation='relu', input_dim=input_dim),
        layers.Dense(256, activation='relu'),
        layers.Dense(output_dim, activation='tanh')
    ])
    return model

def build_discriminator(input_dim):
    """Creates a GAN Discriminator model."""
    model = tf.keras.Sequential([
        layers.Dense(256, activation='relu', input_shape=(input_dim,)),
        layers.Dense(128, activation='relu'),
        layers.Dense(1, activation='sigmoid')
    ])
    return model

def train_gan(generator, discriminator, epochs, batch_size, X_train):
    gan_input_dim = X_train.shape[1]
    gan = models.Sequential([generator, discriminator])
    discriminator.compile(optimizer='adam', loss='binary_crossentropy')
    gan.compile(optimizer='adam', loss='binary_crossentropy')

    for epoch in range(epochs):
        noise = np.random.normal(0, 1, (batch_size, gan_input_dim))
        generated_samples = generator.predict(noise)

        X_fake = np.vstack([generated_samples, X_train[np.random.randint(0, X_train.shape[0], batch_size)]])
        y_fake = np.zeros((2 * batch_size, 1))
        y_fake[:batch_size] = 1

        discriminator.trainable = True
        discriminator.train_on_batch(X_fake, y_fake)

        noise = np.random.normal(0, 1, (batch_size, gan_input_dim))
        y_gan = np.ones((batch_size, 1))

        discriminator.trainable = False
        gan.train_on_batch(noise, y_gan)

    return generator

def generate_synthetic_samples(generator, num_samples, input_dim):
    noise = np.random.normal(0, 1, (num_samples, input_dim))
    return generator.predict(noise)

def load_yara_rules(directory):
    features = []
    labels = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                file_path = os.path.join(root, file)
                features.append(parse_yara_rule(file_path))
                labels.append("malware")
    return np.array(features), labels

# Load and Merge Datasets
yara_repo_path = "./signature-base/yara"
X_yara, labels_yara = load_yara_rules(yara_repo_path)
y_encoded_yara = LabelEncoder().fit_transform(labels_yara)
scaler = StandardScaler()
X_yara = scaler.fit_transform(X_yara)

# Train GAN for Data Augmentation
generator = build_generator(input_dim=6, output_dim=6)
discriminator = build_discriminator(input_dim=6)
gan_generator = train_gan(generator, discriminator, epochs=2000, batch_size=32, X_train=X_yara)

# Generate Synthetic Samples
X_synthetic = generate_synthetic_samples(gan_generator, 1000, 6)
labels_synthetic = np.random.choice(['Benign', 'Trojan', 'Ransomware', 'Adware'], 1000)
y_synthetic = LabelEncoder().fit_transform(labels_synthetic)

# Merge with Original Dataset
X_final = np.vstack((X_yara, X_synthetic))
y_final = np.concatenate((y_encoded_yara, y_synthetic))

# Train-Test Split and Model Training
X_train, X_test, y_train, y_test = train_test_split(X_final, y_final, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
predictions = model.predict(X_test)

print("Model Accuracy:", accuracy_score(y_test, predictions))
print("Classification Report:")
print(classification_report(y_test, predictions, target_names=["Malware", "Benign", "Trojan", "Ransomware", "Adware"]))
