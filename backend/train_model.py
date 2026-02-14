import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# 1. THE DATASET (A mix of safe and malicious URL 'DNA')
# Features: [Length, Dot_Count, Hyphen_Count, Digit_Count, Has_At_Symbol, Is_HTTPS]
# Labels: 0 = Safe, 1 = Malicious
data = [
    [15, 1, 0, 0, 0, 1, 0],  # google.com (Safe)
    [22, 2, 0, 0, 0, 1, 0],  # apple.com (Safe)
    [120, 5, 4, 15, 1, 0, 1],# login-verify-bank-security-update.cc (Malicious)
    [95, 4, 2, 10, 1, 0, 1], # bit.ly/3xJk9L2 (Suspicious/Malicious)
    [18, 1, 0, 0, 0, 1, 0],  # nasa.gov (Safe)
    [140, 6, 3, 22, 1, 0, 1] # free-bitcoins-now-click-here.net (Malicious)
]

columns = ['len', 'dots', 'hyphens', 'digits', 'at_symbol', 'https', 'label']
df = pd.DataFrame(data, columns=columns)

# 2. SEPARATE FEATURES AND LABELS
X = df.drop('label', axis=1)
y = df['label']

# 3. TRAIN THE RANDOM FOREST MODEL
# We use 100 'trees' to make a decision
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# 4. SAVE THE BRAIN
# Ensure backend folder exists
if not os.path.exists('backend'):
    os.makedirs('backend')

joblib.dump(model, 'backend/tice_brain.joblib')
print("✅ SUCCESS: TICE AI Brain has been trained and saved!")