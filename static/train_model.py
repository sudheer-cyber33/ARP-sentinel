import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Set random seed for reproducibility
np.random.seed(42)
n_samples = 6000

# Features:
# 1. packet_rate (packets/sec)
# 2. time_delta (seconds since last packet for this IP)
# 3. is_gratuitous (1 = unsolicited broadcast reply, 0 = standard reply/request)
# 4. burst_count (number of frames received in a 2-second sliding window)

samples_per_class = n_samples // 3

# Class 0: BENIGN_CHANGE (Legitimate hardware swap, DHCP renewal, waking from sleep)
benign_rate = np.random.uniform(0.1, 2.0, samples_per_class)
benign_time_delta = np.random.uniform(20.0, 7200.0, samples_per_class)
benign_gratuitous = np.random.choice([0, 1], size=samples_per_class, p=[0.9, 0.1])
benign_burst = np.random.randint(1, 4, samples_per_class)
y_benign = np.zeros(samples_per_class)

# Class 1: SUSPICIOUS_ALERT (Network scanner, port probing, irregular timing)
suspicious_rate = np.random.uniform(2.5, 7.5, samples_per_class)
suspicious_time_delta = np.random.uniform(3.0, 25.0, samples_per_class)
suspicious_gratuitous = np.random.choice([0, 1], size=samples_per_class, p=[0.6, 0.4])
suspicious_burst = np.random.randint(4, 9, samples_per_class)
y_suspicious = np.ones(samples_per_class)

# Class 2: MALICIOUS_ATTACK (ARP Poisoning, MITM flooding, Ettercap/Arpspoof)
attack_rate = np.random.uniform(8.0, 60.0, samples_per_class)
attack_time_delta = np.random.uniform(0.01, 2.0, samples_per_class)
attack_gratuitous = np.random.choice([0, 1], size=samples_per_class, p=[0.05, 0.95])
attack_burst = np.random.randint(10, 65, samples_per_class)
y_attack = np.full(samples_per_class, 2)

# Assemble feature matrix
X = np.vstack([
    np.column_stack([benign_rate, benign_time_delta, benign_gratuitous, benign_burst]),
    np.column_stack([suspicious_rate, suspicious_time_delta, suspicious_gratuitous, suspicious_burst]),
    np.column_stack([attack_rate, attack_time_delta, attack_gratuitous, attack_burst])
])
y = np.concatenate([y_benign, y_suspicious, y_attack])

# Export synthetic dataset to CSV
df = pd.DataFrame(X, columns=['packet_rate', 'time_delta', 'is_gratuitous', 'burst_count'])
df['target'] = y
df.to_csv('network_arp_dataset.csv', index=False)
print("[+] Dataset exported: network_arp_dataset.csv (6,000 samples)")

# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Train lightweight Random Forest Classifier
classifier = RandomForestClassifier(n_estimators=60, max_depth=7, random_state=42)
classifier.fit(X_train, y_train)

# Evaluate
y_pred = classifier.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"[+] Model Accuracy: {acc * 100:.2f}%")
print(classification_report(y_test, y_pred, target_names=['BENIGN_CHANGE', 'SUSPICIOUS_ALERT', 'MALICIOUS_ATTACK']))

# Export trained model
joblib.dump(classifier, 'arp_classifier.pkl')
print("[+] Model exported successfully: arp_classifier.pkl")