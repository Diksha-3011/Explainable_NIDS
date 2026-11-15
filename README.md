# XNIDS — FastAPI backend

This package migrates the Flask backend to FastAPI while preserving the existing HTML, CSS, and JavaScript UI files. Existing page URLs and API paths are retained.

## Requirements

- Windows 10/11, 64-bit
- Python 3.13 (recommended; do not use the Python 3.15 environment for this project yet)
- The saved model files in `models/` must be from the same training run and compatible with the installed scikit-learn/XGBoost versions.

## Run on Windows (PowerShell)

Open PowerShell in the folder containing `app.py`, then run:

```powershell
py -3.13 -m venv .venv313
.\.venv313\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. API docs: `http://127.0.0.1:8000/docs`.

If `.venv313` already exists, skip the `venv` creation command and activate it. Keep the server terminal open while using the website. Stop the server with Ctrl+C.

## Optional one-click start

Double-click `run_windows.bat`. It uses Python 3.13, creates `.venv313` if missing, installs dependencies, and starts the FastAPI server. The first run requires an internet connection for package installation.

## Included endpoints

- `GET /api/status`
- `GET /api/models`
- `GET /api/history`
- `POST /api/predict` (JSON body keyed by feature names)
- `POST /api/upload` (multipart field named `file`)

## Model files

Expected files in `models/` include `random_forest.pkl`, `decision_tree.pkl`, `xgboost.pkl`, `scaler.pkl`, `label_encoder .pkl` (note the space in this existing filename), and `features.pkl`. The app can start even if a model fails to load, but prediction requires all three configured classifiers and compatible feature preprocessing artifacts. Check `/api/status` for model-loading errors.

SHAP explanations are optional. If SHAP is unavailable or incompatible, the application falls back to model feature importance when the selected estimator supports it.

## Validation notes

Python syntax and template route rendering are checked in the build environment. A full prediction test depends on the provided pickled model artifacts being compatible with the target Python and dependency versions. Model confidence is not a guarantee of prediction correctness.

## Streaming CSV analysis and attack explanations

The upload page now uses `POST /api/upload/stream` and receives newline-delimited JSON events. The page adds rows in batches as predictions are completed, shows a file-level verdict, and shows SHAP/model-feature explanations for detected attack rows. The existing HTML templates and CSS layout are unchanged; the upload JavaScript and backend API integration were updated. `/api/upload` remains available as a backward-compatible non-streaming endpoint.

The verdict is model-based: “No attacks detected” means the model classified all successfully analyzed flows as benign; it is not a guarantee that the file contains no real-world attacks. Failed rows are reported separately and are never counted as benign.
