from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from threading import Lock
from urllib.parse import quote, urlencode
from pathlib import Path
import pickle, json, traceback
import numpy as np
import pandas as pd
import joblib

app = FastAPI(title="Explainable Network Intrusion Detection System", version="2.0.0")
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Keep the existing Flask-style Jinja calls working without changing the UI files.
def template_url_for(endpoint, **values):
    if endpoint == "static":
        filename = values.pop("filename", "")
        path = "/static/" + quote(str(filename).lstrip("/"), safe="/")
        query = urlencode(values)
        return f"{path}?{query}" if query else path
    return str(app.url_path_for(endpoint, **values))

templates.env.globals["url_for"] = template_url_for
history_lock = Lock()
BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
HISTORY_FILE = BASE_DIR / "history.json"
FEATURES_FILE = BASE_DIR / "feature_columns.json"
ALLOWED_EXTENSIONS = {".csv", ".xlsx", ".xls"}
# Exact class order printed by the uploaded CICIDS2017 notebook's LabelEncoder.
NOTEBOOK_CLASSES = [
    "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk",
    "DoS Slowhttptest", "DoS slowloris", "FTP-Patator", "Heartbleed",
    "Infiltration", "PortScan", "SSH-Patator", "Web Attack – Brute Force",
    "Web Attack – Sql Injection", "Web Attack – XSS"
]
# These columns were constant in the notebook's training dataset and were removed
# before fitting the saved models. Never ask the user to enter them.

# Class counts copied from the user's CICIDS2017 notebook (combined 8 CSV files).
# These are dataset distribution counts, not live prediction counts.
CICIDS_LABEL_COUNTS = {
    "BENIGN": 2273097,
    "DoS Hulk": 231073,
    "PortScan": 158930,
    "DDoS": 128027,
    "DoS GoldenEye": 10293,
    "FTP-Patator": 7938,
    "SSH-Patator": 5897,
    "DoS slowloris": 5796,
    "DoS Slowhttptest": 5499,
    "Bot": 1966,
    "Web Attack – Brute Force": 1507,
    "Web Attack – XSS": 652,
    "Infiltration": 36,
    "Web Attack – Sql Injection": 21,
    "Heartbleed": 11,
}
CICIDS_TOTAL_ROWS = sum(CICIDS_LABEL_COUNTS.values())
CICIDS_BENIGN_ROWS = CICIDS_LABEL_COUNTS["BENIGN"]
CICIDS_ATTACK_ROWS = CICIDS_TOTAL_ROWS - CICIDS_BENIGN_ROWS

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
        "encoder": ["label_encoder.pkl", "label_encoder .pkl", "label_encoder.joblib", "encoder.pkl"],
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
    # Keep the exact 70 numeric input features used by the saved notebook models.
    # Removing constant columns here would cause a feature-count mismatch at inference time.
    artifacts["features"] = [f for f in artifacts["features"] if f != "Label"]
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
    with history_lock:
        history = read_history()
        history.insert(0, item)
        temp_file = HISTORY_FILE.with_suffix(".tmp")
        temp_file.write_text(json.dumps(history[:100], indent=2), encoding="utf-8")
        temp_file.replace(HISTORY_FILE)

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
    required_models = ["Random Forest", "Decision Tree", "XGBoost"]
    missing_models = [name for name in required_models if art["models"].get(name) is None]
    if missing_models:
        raise RuntimeError("Required models not loaded: " + ", ".join(missing_models) + ". Check the saved model files in the models folder.")
    expected = art["features"]
    missing = [c for c in expected if c not in frame.columns]
    if missing:
        raise ValueError("Missing required features: " + ", ".join(missing[:8]) + ("..." if len(missing)>8 else ""))
    x = frame[expected].replace([np.inf, -np.inf], np.nan).fillna(0)
    x_scaled = art["scaler"].transform(x) if art.get("scaler") is not None else x

    results = []
    for name in required_models:
        model = art["models"][name]
        pred = model.predict(x_scaled)[0]
        label = label_for(art, pred)
        confidence = None
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(x_scaled)[0]
            best_index = int(np.argmax(probs))
            confidence = float(probs[best_index])
            if hasattr(model, "classes_"):
                label = label_for(art, model.classes_[best_index])
        results.append({"model": name, "prediction": label, "confidence": confidence})

    # Majority vote determines the final class; confidence is the mean of the
    # three models' individual confidence estimates (when available).
    votes = {}
    for item in results:
        votes[item["prediction"]] = votes.get(item["prediction"], 0) + 1
    final_label = max(votes, key=lambda label: (votes[label], next((i for i, r in enumerate(results) if r["prediction"] == label), 99)))
    confidence_values = [r["confidence"] for r in results if r["confidence"] is not None]
    avg_conf = float(np.mean(confidence_values)) if confidence_values else None
    explanation = build_explanation(x, x_scaled, art, final_label)
    return {"prediction": final_label, "confidence": avg_conf, "models": results,
            "is_attack": final_label.strip().upper() not in {"BENIGN", "BENIGN TRAFFIC"},
            "explanation": explanation}



def predict_batch(frame, art):
    """Vectorized model inference for a batch of flows; explanations are generated only for attack rows."""
    required_models = ["Random Forest", "Decision Tree", "XGBoost"]
    missing_models = [name for name in required_models if art["models"].get(name) is None]
    if missing_models:
        raise RuntimeError("Required models not loaded: " + ", ".join(missing_models))
    expected = art["features"]
    x = frame[expected].replace([np.inf, -np.inf], np.nan).fillna(0)
    x_scaled = art["scaler"].transform(x) if art.get("scaler") is not None else x
    model_labels = []
    model_confidences = []
    for name in required_models:
        model = art["models"][name]
        preds = model.predict(x_scaled)
        labels = [label_for(art, pred) for pred in preds]
        confs = [None] * len(labels)
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(x_scaled)
            classes = list(getattr(model, "classes_", []))
            confs = [float(np.max(row)) for row in probs]
            if classes:
                labels = [label_for(art, classes[int(np.argmax(row))]) for row in probs]
        model_labels.append(labels)
        model_confidences.append(confs)
    outputs = []
    for i in range(len(frame)):
        per_model = [
            {"model": required_models[j], "prediction": model_labels[j][i],
             "confidence": model_confidences[j][i]}
            for j in range(len(required_models))
        ]
        votes = {}
        for item in per_model:
            votes[item["prediction"]] = votes.get(item["prediction"], 0) + 1
        final_label = max(
            votes,
            key=lambda label: (
                votes[label],
                next((k for k, item in enumerate(per_model) if item["prediction"] == label), 99)
            )
        )
        conf_values = [item["confidence"] for item in per_model if item["confidence"] is not None]
        confidence = float(np.mean(conf_values)) if conf_values else None
        is_attack = final_label.strip().upper() not in {"BENIGN", "BENIGN TRAFFIC"}
        outputs.append({
            "prediction": final_label, "confidence": confidence,
            "models": per_model, "is_attack": is_attack,
            "explanation": None
        })
    return outputs, x, x_scaled


def explain_attack_batch(raw_frame, model_input, art, outputs):
    """Attach SHAP/feature-importance explanations to attack predictions only."""
    for i, result in enumerate(outputs):
        if result.get("is_attack"):
            try:
                result["explanation"] = build_explanation(
                    raw_frame.iloc[[i]], model_input[i:i+1], art, result["prediction"]
                )
            except Exception as exc:
                result["explanation"] = {
                    "method": "unavailable",
                    "summary": f"Attack class predicted as {result['prediction']}; explanation unavailable: {exc}",
                    "top_features": []
                }
    return outputs

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={
        "page": "dashboard", "class_counts": CICIDS_LABEL_COUNTS,
        "total_rows": CICIDS_TOTAL_ROWS, "benign_rows": CICIDS_BENIGN_ROWS,
        "attack_rows": CICIDS_ATTACK_ROWS
    })

@app.get("/input", response_class=HTMLResponse)
async def input_page(request: Request):
    return templates.TemplateResponse(request=request, name="input.html", context={"page": "input"})

@app.get("/input/manual", response_class=HTMLResponse)
async def manual_input_page(request: Request):
    art = await run_in_threadpool(artifacts)
    return templates.TemplateResponse(request=request, name="manual.html", context={
        "page": "input", "features": art["features"]
    })

@app.get("/input/upload", response_class=HTMLResponse)
async def upload_input_page(request: Request):
    return templates.TemplateResponse(request=request, name="upload.html", context={"page": "input"})

@app.get("/models", response_class=HTMLResponse)
async def models_page(request: Request):
    art = await run_in_threadpool(artifacts)
    benchmarks = {"Decision Tree": 0.998264, "Random Forest": 0.998281, "XGBoost": 0.996549}
    history = await run_in_threadpool(read_history)
    last_models = {m.get("model"): m for item in history for m in item.get("models", []) if not m.get("error")}
    model_rows = [{"name": name, "loaded": name in art["models"], "test_accuracy": benchmarks.get(name),
                   "last_prediction": last_models.get(name, {}).get("prediction"),
                   "last_confidence": last_models.get(name, {}).get("confidence"), "dataset": "CICIDS2017"}
                  for name in ["Random Forest", "Decision Tree", "XGBoost"]]
    return templates.TemplateResponse(request=request, name="models.html", context={
        "page": "models", "model_rows": model_rows
    })

@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    return templates.TemplateResponse(request=request, name="history.html", context={"page": "history"})

@app.get("/api/status")
async def api_status():
    art = await run_in_threadpool(artifacts)
    return {"ready": bool(art["models"]), "models": list(art["models"].keys()),
            "feature_count": len(art["features"]), "features": art["features"],
            "errors": art["errors"], "message": "Models loaded" if art["models"] else "Model files not found"}

@app.get("/api/models")
async def api_models():
    art = await run_in_threadpool(artifacts)
    benchmarks = {"Decision Tree": 0.998264, "Random Forest": 0.998281, "XGBoost": 0.996549}
    history = await run_in_threadpool(read_history)
    last_models = {m.get("model"): m for item in history for m in item.get("models", []) if not m.get("error")}
    rows = []
    for name in ["Random Forest", "Decision Tree", "XGBoost"]:
        rows.append({"name": name, "loaded": name in art["models"],
                     "test_accuracy": benchmarks.get(name),
                     "last_prediction": last_models.get(name, {}).get("prediction"),
                     "last_confidence": last_models.get(name, {}).get("confidence"),
                     "dataset": "CICIDS2017"})
    return {"models": rows, "note": "Dataset test accuracy is a benchmark. Live input shows each loaded model's prediction and confidence; per-row accuracy requires a known ground-truth label."}

@app.get("/api/history")
async def api_history():
    return await run_in_threadpool(read_history)

@app.post("/api/predict")
async def api_predict(request: Request):
    try:
        data = await request.json()
        if not isinstance(data, dict):
            return JSONResponse({"error": "Request body must be a JSON object."}, status_code=400)
        art = await run_in_threadpool(artifacts)
        frame = await run_in_threadpool(prepare_frame, data, art)
        result = await run_in_threadpool(predict_frame, frame, art)
        item = {"source": "Manual entry", **result,
                "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")}
        await run_in_threadpool(add_history, item)
        return item
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@app.post("/api/upload/stream")
async def api_upload_stream(file: UploadFile = File(...)):
    """Stream one JSON event per processed batch so the UI can update incrementally."""
    if not file.filename:
        return JSONResponse({"error": "Choose a CSV or Excel file first."}, status_code=400)
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return JSONResponse({"error": "Only CSV, XLSX and XLS files are supported."}, status_code=400)
    content = await file.read()
    filename = file.filename

    def load_upload():
        import io
        stream = io.BytesIO(content)
        df = pd.read_csv(stream) if ext == ".csv" else pd.read_excel(stream)
        df.columns = [str(c).strip() for c in df.columns]
        art = artifacts()
        expected = art["features"]
        missing = [c for c in expected if c not in df.columns]
        if missing:
            raise ValueError(
                f"File is missing {len(missing)} model feature columns. "
                f"Examples: {', '.join(missing[:8])}"
            )
        return df, art, expected

    try:
        df, art, expected = await run_in_threadpool(load_upload)
    except Exception as exc:
        return JSONResponse({"error": f"Could not read or validate file: {exc}"}, status_code=400)

    async def events():
        total = len(df)
        batch_size = 8
        yield json.dumps({
            "type": "start", "filename": filename, "rows": total,
            "batch_size": batch_size
        }) + "\n"
        completed = 0
        attack_count = 0
        benign_count = 0
        failed_count = 0
        all_results = []
        for offset in range(0, total, batch_size):
            batch = df.iloc[offset:offset + batch_size]
            try:
                predictions, raw_frame, model_input = await run_in_threadpool(
                    lambda b=batch: predict_batch(b[expected], art)
                )
                predictions = await run_in_threadpool(
                    explain_attack_batch, raw_frame, model_input, art, predictions
                )
                batch_results = []
                for j, result in enumerate(predictions):
                    row_result = {"row": offset + j + 1, **result}
                    batch_results.append(row_result)
                    if row_result.get("is_attack"):
                        attack_count += 1
                    else:
                        benign_count += 1
                all_results.extend(batch_results)
                completed += len(batch_results)
                yield json.dumps({
                    "type": "batch", "completed": completed, "total": total,
                    "results": batch_results, "attack_count": attack_count,
                    "benign_count": benign_count, "failed_count": failed_count
                }, default=str) + "\n"
            except Exception as exc:
                batch_results = [
                    {"row": offset + j + 1, "error": str(exc), "is_attack": None,
                     "prediction": None, "confidence": None, "explanation": None}
                    for j in range(len(batch))
                ]
                all_results.extend(batch_results)
                failed_count += len(batch_results)
                completed += len(batch_results)
                yield json.dumps({
                    "type": "batch", "completed": completed, "total": total,
                    "results": batch_results, "attack_count": attack_count,
                    "benign_count": benign_count, "failed_count": failed_count
                }, default=str) + "\n"
        # Persist one upload summary to history.
        summary = {
            "source": "CSV/Excel upload", "filename": filename, "rows": total,
            "prediction": "Attack detected" if attack_count else (
                "No attacks detected" if failed_count == 0 else "Analysis incomplete"
            ),
            "is_attack": attack_count > 0, "attack_count": attack_count,
            "benign_count": benign_count, "failed_count": failed_count,
            "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        await run_in_threadpool(add_history, summary)
        yield json.dumps({
            "type": "complete", "filename": filename, "rows": total,
            "results": all_results, "attack_count": attack_count,
            "benign_count": benign_count, "failed_count": failed_count,
            "verdict": "attack_detected" if attack_count else (
                "no_attacks_detected" if failed_count == 0 else "analysis_incomplete"
            )
        }, default=str) + "\n"

    return StreamingResponse(events(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...)):
    """Backward-compatible non-streaming upload endpoint."""
    if not file.filename:
        return JSONResponse({"error": "Choose a CSV or Excel file first."}, status_code=400)
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return JSONResponse({"error": "Only CSV, XLSX and XLS files are supported."}, status_code=400)
    try:
        content = await file.read()
        filename = file.filename
        def analyse_upload():
            import io
            stream = io.BytesIO(content)
            df = pd.read_csv(stream) if ext == ".csv" else pd.read_excel(stream)
            df.columns = [str(c).strip() for c in df.columns]
            art = artifacts()
            expected = art["features"]
            missing = [c for c in expected if c not in df.columns]
            if missing:
                raise ValueError(f"File is missing {len(missing)} model feature columns. Examples: {', '.join(missing[:8])}")
            outputs = []
            for offset in range(0, len(df), 8):
                batch = df.iloc[offset:offset+8]
                preds, raw, scaled = predict_batch(batch[expected], art)
                preds = explain_attack_batch(raw, scaled, art, preds)
                outputs.extend({"row": offset+j+1, **r} for j, r in enumerate(preds))
            attacks = sum(1 for r in outputs if r.get("is_attack"))
            failed = sum(1 for r in outputs if r.get("error"))
            summary = {"source": "CSV/Excel upload", "filename": filename, "rows": len(df),
                       "prediction": "Attack detected" if attacks else ("No attacks detected" if not failed else "Analysis incomplete"),
                       "is_attack": attacks > 0, "attack_count": attacks,
                       "benign_count": len(outputs)-attacks-failed, "failed_count": failed,
                       "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")}
            add_history(summary)
            return {"filename": filename, "rows": len(df), "results": outputs,
                    "attack_count": attacks, "benign_count": len(outputs)-attacks-failed,
                    "failed_count": failed,
                    "verdict": "attack_detected" if attacks else ("no_attacks_detected" if not failed else "analysis_incomplete")}
        return await run_in_threadpool(analyse_upload)
    except Exception as exc:
        return JSONResponse({"error": f"Could not read or analyse file: {exc}"}, status_code=400)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
