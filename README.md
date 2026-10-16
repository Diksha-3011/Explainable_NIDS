# XNIDS System — Fresh Flask Project

Frontend: HTML, CSS, JavaScript. Backend: Flask. This project does **not** train models. Put your saved model artifacts in `models/`.

## Run on Windows

```powershell
py -m pip install -r requirements.txt
py app.py
```

Open http://127.0.0.1:5000 and keep the terminal running.

## Model files

Copy artifacts from the same notebook training run into `models/`:
- `random_forest.pkl`
- `decision_tree.pkl`
- `xgboost.pkl` (only if you have this saved model)
- `scaler.pkl`
- `label_encoder.pkl`
- `features.pkl` (list of model feature names; optional because `feature_columns.json` has the 70 names from the uploaded notebook)

The notebook provided in this conversation visibly trains Decision Tree and Random Forest, with test accuracies 99.8373% and 99.8281% respectively. Its visible cells do not show an XGBoost training result. The app shows XGBoost as not loaded until you provide the saved artifact. Accuracy shown on the Models page is the notebook's dataset-level test accuracy, not accuracy for one individual user input. Individual predictions show confidence if the model supports `predict_proba`.

## Important preprocessing compatibility

The notebook removes constant columns, keeps numeric columns, replaces infinity with missing values, fills missing numeric values with medians, then standard-scales the input before prediction. The saved `scaler.pkl`, models and feature list must be from the same run. If `features.pkl` is a pandas Index/NumPy array/list, the app can use it. A median-imputation object is not separately saved in the notebook cells, so uploaded data is filled with zero for remaining missing values; for exact reproducibility, save and load the notebook's training medians as well.

## Features

- Dashboard, User Input, Models & Accuracy, History navigation.
- Manual entry form is rendered by Flask using the loaded saved feature list (falling back to the notebook feature list), so fields remain visible even if JavaScript API status polling fails.
- Benign and PortScan illustrative default values; users can edit values before analysis.
- CSV, XLSX, XLS upload; file must include all model feature columns.
- Model-level predictions and confidence, a simple confidence chart, local JSON history.
- No model training script is included.

## API endpoints (Flask)

- `GET /api/status`
- `GET /api/models`
- `GET /api/history`
- `POST /api/predict` JSON body keyed by feature names
- `POST /api/upload` multipart form field `file`

## Limitations

- Preset samples are illustrative, not actual captured CICIDS2017 rows; they do not guarantee a particular label.
- Confidence is not a guarantee of correctness.
- Model metrics only reflect the values recorded in the notebook and should not be treated as independently validated.

## Recent fixes
- The eight columns that were constant in the supplied notebook (`Bwd PSH Flags`, `Bwd URG Flags`, the Fwd/Bwd Avg Bulk columns) are filtered from the manual form if present in an older feature artifact.
- Manual prediction results include the predicted attack class, per-model prediction/confidence, and an explanation panel. SHAP is used when it is installed and supported by the saved tree model; otherwise the app clearly labels its fallback as global feature importance.
- The Models page displays notebook test-set accuracy separately from each model's latest live prediction and confidence. Live confidence is not accuracy; accuracy for one flow needs its true label.
- CSV/Excel inference uses the same preprocessing path as manual inference, avoiding accidental double-scaling.

Place the saved models, scaler, label encoder and feature list from the same notebook training run in `models/`. Expected filenames include `random_forest.pkl`, `decision_tree.pkl`, `xgboost.pkl`, `scaler.pkl`, `label_encoder.pkl` and `features.pkl`. Restart Flask after copying the files.
