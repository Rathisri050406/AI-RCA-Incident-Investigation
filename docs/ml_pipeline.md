# ML pipeline
`data_loader` (CIC-IDS2017, BGL, HDFS, custom CSV, synthetic) → `preprocessor.clean` (column mapping, inf→NaN, dropna, de-duplicate, binarise label) → `feature_engineering.build_features` → stratified 80/20 split → fit on train → metrics on test → `detector.pkl`, `metrics.json`, plots.
Primary model XGBoost (falls back to GradientBoosting if xgboost is missing, and records which). Baselines: Random Forest, Logistic Regression.
Detection tiers: confidence <0.35 NORMAL, 0.35-0.7 SUSPICIOUS, ≥0.7 INCIDENT. Log rules: ≥5 failed logins in a 5-minute window, ≥5 DB/app errors.
