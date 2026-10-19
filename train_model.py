import csv
import math
import joblib
from sklearn.ensemble import IsolationForest

X = []

with open("normal_traffic.csv", newline="") as file:
    for row in csv.reader(file):
        if len(row) != 3:
            continue

        try:
            values = [float(value) for value in row]
        except ValueError:
            continue

        if all(math.isfinite(value) for value in values):
            X.append(values)

if len(X) < 100:
    raise ValueError(
        f"Only {len(X)} valid rows found. "
        "Collect more baseline traffic first."
    )

model = IsolationForest(
    contamination=0.1,
    random_state=42
)

model.fit(X)
joblib.dump(model, "ids_model.joblib")

print(f"Model trained on {len(X)} observations.")
print("Saved to ids_model.joblib")
