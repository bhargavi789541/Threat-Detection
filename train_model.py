import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os

# --- Load Dataset ---
df = pd.read_csv("sample_cyber_threat_dataset.csv")

# --- Feature & Target Separation ---
if "IsThreat" not in df.columns:
    raise ValueError("❌ 'IsThreat' column not found in the dataset!")

X = df.drop("IsThreat", axis=1)
y = df["IsThreat"]

# --- Split into Train/Test Sets ---
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# --- Initialize & Train Model ---
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# --- Evaluation (Optional but Recommended) ---
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print("✅ Model trained successfully!")
print("🔍 Accuracy on test set:", acc)
print("📊 Classification Report:\n", classification_report(y_test, y_pred))

# --- Save Model ---
MODEL_PATH = "cyber_threat_model.pkl"
with open(MODEL_PATH, "wb") as f:
    pickle.dump(model, f)

print(f"💾 Model saved as '{MODEL_PATH}'")

# --- (Optional) Save Feature Columns for Later Use ---
feature_path = "model_features.pkl"
with open(feature_path, "wb") as f:
    pickle.dump(X.columns.tolist(), f)

print(f"🧠 Feature column names saved as '{feature_path}'")
