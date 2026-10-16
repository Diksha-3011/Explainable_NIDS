from flask import Flask, render_template, request, jsonify
from pathlib import Path
import pickle, json, traceback
import numpy as np
import pandas as pd
import joblib

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
HISTORY_FILE = BASE_DIR / "history.json"
FEATURES_FILE = BASE_DIR / "feature_columns.json"
ALLOWED_EXTENSIONS = {".csv", ".xlsx", ".xls"}
# Exact class order printed by the uploaded CICIDS2017 notebook's LabelEncoder.
NOTEBOOK_CLASSES = [
    "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk",
    "DoS Slowhttptest", "DoS slowloris", "FTP-Patator", "Heartbleed",
    "Infiltration", "PortScan", "SSH-Patator", "Web Attack - Brute Force",
    "Web Attack - Sql Injection", "Web Attack - XSS"
]
# These columns were constant in the notebook's training dataset and were removed
# before fitting the saved models. Never ask the user to enter them.
CONSTANT_ZERO_FEATURES = {
    "Bwd PSH Flags", "Bwd URG Flags", "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate"
}

def load_pickle(path):
    try:
        return joblib.load(path)
    except Exception:
        with open(path, "rb") as f:
            return pickle.load(f)

def load_artifacts():
    features = json.loads(FEATURES_FILE.read_text(encoding="utf-8"))
    artifacts = {"features": features, "models": {}, "scaler": None, "encoder": None, "errors": []}
    files = {
        "Random Forest": ["random_forest.pkl", "random_forest_model.pkl", "rf_model.pkl", "RandomForest.pkl", "random_forest.joblib"],
        "Decision Tree": ["decision_tree.pkl", "decision_tree_model.pkl", "dt_model.pkl", "DecisionTree.pkl", "decision_tree.joblib"],
        "XGBoost": ["xgboost.pkl", "xgboost_model.pkl", "xgb_model.pkl", "XGBoost.pkl", "xgboost.joblib"],
    }
    for name, options in files.items():
        for filename in options:
            path = MODEL_DIR / filename
            if path.exists():
                try:
                    artifacts["models"][name] = load_pickle(path)
                except Exception as e:
                    artifacts["errors"].append(f"{filename}: {e}")
                break
    for key, names in {
        "scaler": ["scaler.pkl", "scaler.joblib", "standard_scaler.pkl"],
        "encoder": ["label_encoder.pkl", "label_encoder.joblib", "encoder.pkl"],
        "features": ["features.pkl", "features.joblib", "feature_order.joblib", "feature_columns.pkl"]
    }.items():
        for name in names:
            path = MODEL_DIR / name
            if path.exists():
                try:
                    value = load_pickle(path)
                    if key == "features":
                        if isinstance(value, (list, tuple, np.ndarray)):
                            artifacts["features"] = [str(x) for x in value]
                        elif hasattr(value, "tolist"):
                            artifacts["features"] = [str(x) for x in value.tolist()]
                    else:
                        artifacts[key] = value
                except Exception as e:
                    artifacts["errors"].append(f"{name}: {e}")
                break
    # Remove the notebook's constant columns even if an older saved feature list contains them.
    artifacts["features"] = [f for f in artifacts["features"] if f not in CONSTANT_ZERO_FEATURES and f != "Label"]
    return artifacts

ARTIFACTS = None
def artifacts():
    global ARTIFACTS
    if ARTIFACTS is None:
        ARTIFACTS = load_artifacts()
    return ARTIFACTS

def read_history():
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8")) if HISTORY_FILE.exists() else []
    except Exception:
        return []

def add_history(item):
    history = read_history()
    history.insert(0, item)
    HISTORY_FILE.write_text(json.dumps(history[:100], indent=2), encoding="utf-8")

def prepare_frame(data, art):
    names = art["features"]
    row = {}
    for name in names:
        value = data.get(name, data.get(name.strip(), 0))
        try:
            number = float(value)
            if not np.isfinite(number):
                number = 0.0
        except (TypeError, ValueError):
            number = 0.0
        row[name] = number
    return pd.DataFrame([row], columns=names)

def label_for(art, pred):
    """Return a readable attack class, never a numeric class ID when it can be decoded."""
    enc = art.get("encoder")
    if enc is not None:
        try:
            # Encoded classifiers usually predict integers; some saved models predict strings.
            value = pred.item() if hasattr(pred, "item") else pred
            if isinstance(value, (int, np.integer, float, np.floating)) or str(value).strip().lstrip("-+").isdigit():
                return str(enc.inverse_transform([int(value)])[0])
            return str(value)
        except Exception:
            pass
    try:
        value = pred.item() if hasattr(pred, "item") else pred
        if isinstance(value, (int, np.integer, float, np.floating)) or str(value).strip().lstrip("-+").isdigit():
            idx = int(value)
            if 0 <= idx < len(NOTEBOOK_CLASSES):
                return NOTEBOOK_CLASSES[idx]
    except Exception:
        pass
    return str(pred)

def build_explanation(raw_frame, model_input, art, prediction):
    """Prefer per-row SHAP values; fall back to trained global feature importance."""
    names = art["features"]
    model = art["models"].get("Random Forest")
    if model is None:
        model = art["models"].get("Decision Tree")
    if model is None:
        model = art["models"].get("XGBoost")
    if model is None:
        return {"method": "unavailable", "summary": "No model is available to explain this prediction.", "top_features": []}

    row = np.asarray(model_input, dtype=float).reshape(1, -1)
    # SHAP is optional at runtime so predictions still work if it is not installed.
    try:
        import shap
        shap_values = shap.TreeExplainer(model).shap_values(row)
        if isinstance(shap_values, list):
            class_idx = 0
            enc = art.get("encoder")
            if enc is not None:
                try:
                    class_idx = int(enc.transform([prediction])[0])
                except Exception:
                    class_idx = 0
            class_idx = min(class_idx, len(shap_values) - 1)
            vals = np.asarray(shap_values[class_idx]).reshape(-1)
        else:
            vals_arr = np.asarray(shap_values)
            if vals_arr.ndim == 3:
                class_idx = 0
                enc = art.get("encoder")
                if enc is not None:
                    try:
                        class_idx = int(enc.transform([prediction])[0])
                    except Exception:
                        class_idx = 0
                vals = vals_arr[0, :, min(class_idx, vals_arr.shape[2] - 1)]
            else:
                vals = vals_arr.reshape(-1)
        order = np.argsort(np.abs(vals))[::-1][:8]
        top = [{"feature": str(names[i]), "value": float(raw_frame.iloc[0][names[i]]),
                "importance": float(abs(vals[i])), "impact": float(vals[i])} for i in order]
        supporting = [item["feature"] for item in top if item["impact"] is not None and item["impact"] > 0][:4]
        opposing = [item["feature"] for item in top if item["impact"] is not None and item["impact"] < 0][:3]
        detail = (f"For this {prediction} prediction, the strongest features supporting the selected class were {', '.join(supporting)}." if supporting else f"The SHAP values show which features influenced the {prediction} prediction.")
        if opposing:
            detail += f" Features pushing against this class included {', '.join(opposing)}."
        detail += " Positive SHAP values push the selected model output toward this class and negative values push away from it. These are model contributions, not proof of causation."
        return {"method": "SHAP", "summary": detail, "top_features": top}
    except Exception:
        pass

    importances = getattr(model, "feature_importances_", None)
    if importances is None or len(importances) != len(names):
        return {"method": "unavailable", "summary": f"The model predicted {prediction}, but this estimator does not expose an explanation method in the current environment.", "top_features": []}
    top_idx = np.argsort(importances)[::-1]
    top = []
    for i in top_idx:
        if float(importances[i]) <= 0:
            continue
        top.append({"feature": str(names[i]), "value": float(raw_frame.iloc[0][names[i]]),
                    "importance": float(importances[i]), "impact": None})
        if len(top) == 8:
            break
    feature_names = [item["feature"] for item in top[:4]]
    summary = f"The model classified this flow as {prediction}. The most influential features learned during training are {', '.join(feature_names)}. Their values and ranking help explain what the model generally pays attention to, but global feature importance does not prove that these features caused this individual prediction. Row-specific SHAP values were not available in this run."
    return {"method": "Feature importance", "summary": summary, "top_features": top}

def predict_frame(frame, art):
    if not art["models"]:
        raise RuntimeError("No model files loaded. Put your saved .pkl files in the models folder and restart Flask.")
    expected = art["features"]
    missing = [c for c in expected if c not in frame.columns]
    if missing:
        raise ValueError("Missing required features: " + ", ".join(missing[:8]) + ("..." if len(missing)>8 else ""))
    x = frame[expected].replace([np.inf, -np.inf], np.nan).fillna(0)
    if art.get("scaler") is not None:
        x_scaled = art["scaler"].transform(x)
    else:
        x_scaled = x
    results = []
    for name, model in art["models"].items():
        try:
            pred = model.predict(x_scaled)[0]
            label = label_for(art, pred)
            confidence = None
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(x_scaled)[0]
                confidence = float(np.max(probs))
                if hasattr(model, "classes_"):
                    pred = model.classes_[int(np.argmax(probs))]
                    label = label_for(art, pred)
            results.append({"model": name, "prediction": label, "confidence": confidence})
        except Exception as e:
            results.append({"model": name, "error": str(e)})
    good = [r for r in results if "error" not in r]
    if not good:
        raise RuntimeError("All loaded models failed. Check that model, scaler and feature list are from the same training run. " + "; ".join(r.get("error","") for r in results))
    votes = {}
    for r in good:
        votes[r["prediction"]] = votes.get(r["prediction"], 0) + 1
    final_label = sorted(votes.items(), key=lambda item: item[1], reverse=True)[0][0]
    confidences = [r["confidence"] for r in good if r["confidence"] is not None]
    avg_conf = float(np.mean(confidences)) if confidences else None
    explanation = build_explanation(x, x_scaled, art, final_label)
    return {"prediction": final_label, "confidence": avg_conf, "models": results,
            "is_attack": final_label.strip().upper() not in {"BENIGN", "BENIGN TRAFFIC"},
            "explanation": explanation}

@app.get("/")
def dashboard():
    return render_template("index.html", page="dashboard")

@app.get("/input")
def input_page():
    art = artifacts()
    return render_template("input.html", page="input", features=art["features"], model_count=len(art["models"]))

@app.get("/models")
def models_page():
    art = artifacts()
    benchmarks = {"Decision Tree": 0.998372559086413, "Random Forest": 0.9982813748208527}
    history = read_history()
    last_models = {m.get("model"): m for item in history for m in item.get("models", []) if not m.get("error")}
    model_rows = [{"name": name, "loaded": name in art["models"], "test_accuracy": benchmarks.get(name),
                   "last_prediction": last_models.get(name, {}).get("prediction"),
                   "last_confidence": last_models.get(name, {}).get("confidence"), "dataset": "CICIDS2017"}
                  for name in ["Random Forest", "Decision Tree", "XGBoost"]]
    return render_template("models.html", page="models", model_rows=model_rows)

@app.get("/history")
def history_page():
    return render_template("history.html", page="history")

@app.get("/api/status")
def api_status():
    art = artifacts()
    return jsonify({"ready": bool(art["models"]), "models": list(art["models"].keys()),
                    "feature_count": len(art["features"]), "features": art["features"],
                    "errors": art["errors"], "message": "Models loaded" if art["models"] else "Model files not found"})

@app.get("/api/models")
def api_models():
    art = artifacts()
    # Notebook output values are test-set benchmark accuracy, not per-input accuracy.
    benchmarks = {"Decision Tree": 0.998372559086413, "Random Forest": 0.9982813748208527}
    history = read_history()
    last_models = {m.get("model"): m for item in history for m in item.get("models", []) if not m.get("error")}
    rows = []
    for name in ["Random Forest", "Decision Tree", "XGBoost"]:
        rows.append({"name": name, "loaded": name in art["models"],
                     "test_accuracy": benchmarks.get(name),
                     "last_prediction": last_models.get(name, {}).get("prediction"),
                     "last_confidence": last_models.get(name, {}).get("confidence"),
                     "dataset": "CICIDS2017"})
    return jsonify({"models": rows, "note": "Dataset test accuracy is a benchmark. Live input shows each loaded model's prediction and confidence; per-row accuracy requires a known ground-truth label."})

@app.get("/api/history")
def api_history():
    return jsonify(read_history())

@app.post("/api/predict")
def api_predict():
    art = artifacts()
    try:
        data = request.get_json(force=True) or {}
        frame = prepare_frame(data, art)
        result = predict_frame(frame, art)
        item = {"source": "Manual entry", **result, "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")}
        add_history(item)
        return jsonify(item)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.post("/api/upload")
def api_upload():
    art = artifacts()
    if "file" not in request.files or not request.files["file"].filename:
        return jsonify({"error": "Choose a CSV or Excel file first."}), 400
    file = request.files["file"]
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "Only CSV, XLSX and XLS files are supported."}), 400
    try:
        df = pd.read_csv(file) if ext == ".csv" else pd.read_excel(file)
        df.columns = [str(c).strip() for c in df.columns]
        expected = art["features"]
        missing = [c for c in expected if c not in df.columns]
        if missing:
            return jsonify({"error": f"File is missing {len(missing)} model feature columns. Examples: {', '.join(missing[:8])}"}), 400
        x = df[expected].replace([np.inf, -np.inf], np.nan).fillna(0)
        # Reuse the same raw-input preprocessing and model path as manual inference.
        outputs = []
        for idx in range(len(x)):
            row = x.iloc[[idx]]
            try:
                outputs.append({"row": idx + 1, **predict_frame(row, {**art, "features": expected})})
            except Exception as e:
                outputs.append({"row": idx + 1, "error": str(e)})
        return jsonify({"filename": file.filename, "rows": len(df), "results": outputs})
    except Exception as e:
        return jsonify({"error": f"Could not read or analyse file: {e}"}), 400

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
