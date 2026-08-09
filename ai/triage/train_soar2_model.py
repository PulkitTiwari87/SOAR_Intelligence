#!/usr/bin/env python3
"""
SOAR2 Model Training Script
============================
Converted from soar2.ipynb (Kaggle notebook).

Pipeline:
  1. Load & merge dataset (KDD Cup 99 via scikit-learn, or CICIDS2017 CSVs if available)
  2. Clean data (drop NaN, inf, keep numeric features)
  3. Merge rare classes into 'other'
  4. BorderlineSMOTE for class imbalance
  5. Regularized XGBoost (n_estimators=300, max_depth=4, gamma=2)
  6. Stratified 3-fold cross-validation
  7. Save: final_intrusion_model.pkl, scaler.pkl, label_encoder.pkl

Usage:
  python train_soar2_model.py                        # Train with KDD Cup 99
  python train_soar2_model.py --data-dir /path/to/csvs  # Train with custom CSVs
"""

import os
import sys
import glob
import warnings
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    balanced_accuracy_score,
)

from imblearn.over_sampling import BorderlineSMOTE
from imblearn.pipeline import Pipeline

from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# ===========================================================
# STEP 1: LOAD DATA
# ===========================================================
def load_cicids_csvs(data_dir):
    """Load CICIDS2017 (or similar) CSV files from a directory."""
    files = glob.glob(os.path.join(data_dir, "**/*.csv"), recursive=True)
    if not files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    df_list = []
    for file in files:
        print(f"  Loading: {file}")
        df_list.append(pd.read_csv(file))

    df = pd.concat(df_list, ignore_index=True)
    print(f"  Combined dataset shape: {df.shape}")
    return df


def load_kdd_cup_99():
    """Load the KDD Cup 99 dataset via scikit-learn and prepare it as a DataFrame."""
    from sklearn.datasets import fetch_kddcup99

    print("  Fetching KDD Cup 99 dataset (10% subset)...")
    kdd = fetch_kddcup99(percent10=True, as_frame=True)
    df = kdd.frame.copy()
    print(f"  Raw KDD shape: {df.shape}")

    # Decode ALL bytes columns to strings first
    for col in df.columns:
        if df[col].dtype == object:
            try:
                df[col] = df[col].apply(lambda x: x.decode("utf-8") if isinstance(x, bytes) else str(x))
            except (AttributeError, UnicodeDecodeError):
                df[col] = df[col].astype(str)

    # Rename the target column to 'label'
    if "labels" in df.columns:
        df.rename(columns={"labels": "label"}, inplace=True)

    # Clean label: remove trailing dots
    df["label"] = df["label"].astype(str).str.rstrip(".")

    # Identify categorical vs numeric columns
    categorical_cols = ["protocol_type", "service", "flag"]
    numeric_cols = [c for c in df.columns if c not in categorical_cols and c != "label"]

    # Convert numeric columns from string/object to actual numeric types
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Label-encode categorical columns (protocol_type, service, flag)
    from sklearn.preprocessing import LabelEncoder as _LE
    for col in categorical_cols:
        if col in df.columns:
            enc = _LE()
            df[col] = enc.fit_transform(df[col].astype(str))
            print(f"  Encoded '{col}': {len(enc.classes_)} categories")

    print(f"  KDD dataset shape after processing: {df.shape}")
    print(f"  Numeric columns: {len([c for c in df.columns if c != 'label'])}")
    return df


# ===========================================================
# STEP 2: CLEAN DATA
# ===========================================================
def clean_data(df):
    """Clean the DataFrame: strip column names, rename label, drop NaN/inf, keep numeric."""
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Standardize the label column name
    possible_labels = ["Label", "label", "Attack", "attack", "class", "Class", "labels"]
    label_col = None
    for col in possible_labels:
        if col in df.columns:
            label_col = col
            break

    if label_col is None:
        raise ValueError(f"No label column found. Available columns: {list(df.columns)}")

    if label_col != "label":
        df.rename(columns={label_col: "label"}, inplace=True)
    print(f"  Label column: '{label_col}'")

    # Separate label
    y = df["label"]
    X = df.drop("label", axis=1)

    # Keep only numeric features (categorical should already be encoded)
    numeric_X = X.select_dtypes(include=[np.number])
    if numeric_X.shape[1] == 0:
        raise ValueError("No numeric features found after cleaning. Check data loading.")
    X = numeric_X

    # Recombine
    df = X.copy()
    df["label"] = y.values

    # Remove nulls and infinities
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    print(f"  Numeric features: {X.shape[1]}")

    # Reduce size for speed (cap at 200K samples)
    if len(df) > 200000:
        print(f"  Sampling down from {len(df)} to 200,000 rows...")
        df = df.sample(200000, random_state=42)

    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"  Cleaned shape: {df.shape}")
    return df


# ===========================================================
# STEP 3: MERGE RARE CLASSES
# ===========================================================
def merge_rare_classes(df, threshold=50):
    """Merge classes with fewer than `threshold` samples into 'other'."""
    class_counts = df["label"].value_counts()
    rare_classes = class_counts[class_counts < threshold].index
    if len(rare_classes) > 0:
        print(f"  Merging {len(rare_classes)} rare classes (< {threshold} samples) into 'other'")
    df["label"] = df["label"].apply(lambda x: "other" if x in rare_classes else x)
    df["label"] = df["label"].astype(str)
    return df


# ===========================================================
# STEP 4-11: FULL TRAINING PIPELINE
# ===========================================================
def train_pipeline(df):
    """Run the full SOAR2 training pipeline."""

    # ------- ENCODE LABELS -------
    le = LabelEncoder()
    df["label_encoded"] = le.fit_transform(df["label"])

    n_classes = len(le.classes_)
    print(f"\n{'='*60}")
    print(f"  CLASSES ({n_classes}):")
    print(f"{'='*60}")
    for i, cls in enumerate(le.classes_):
        count = (df["label"] == cls).sum()
        print(f"    [{i}] {cls}: {count} samples")

    # ------- FEATURES & TARGET -------
    X = df.drop(columns=["label", "label_encoded"])
    y = df["label_encoded"]

    feature_names = list(X.columns)
    print(f"\n  Features ({len(feature_names)}): {feature_names[:10]}{'...' if len(feature_names) > 10 else ''}")

    # ------- TRAIN-TEST SPLIT -------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"\n  Train: {X_train.shape[0]} samples")
    print(f"  Test:  {X_test.shape[0]} samples")

    # ------- SMOTE -------
    # Determine safe k_neighbors based on smallest class in training set
    min_class_count = pd.Series(y_train).value_counts().min()
    safe_k = min(5, max(1, min_class_count - 1))
    print(f"  SMOTE k_neighbors: {safe_k} (min class has {min_class_count} samples)")

    smote = BorderlineSMOTE(k_neighbors=safe_k, random_state=42)

    # ------- REGULARIZED XGBOOST -------
    model = XGBClassifier(
        n_estimators=300,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.7,
        colsample_bytree=0.7,
        gamma=2,
        min_child_weight=5,
        reg_alpha=1,
        reg_lambda=2,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
    )

    # ------- PIPELINE -------
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("smote", smote),
        ("model", model),
    ])

    # ------- TRAIN -------
    print(f"\n{'='*60}")
    print("  TRAINING MODEL...")
    print(f"{'='*60}")
    pipeline.fit(X_train, y_train)

    # ------- STANDARD TEST EVALUATION -------
    y_pred = pipeline.predict(X_test)

    y_pred_labels = le.inverse_transform(y_pred)
    y_test_labels = le.inverse_transform(y_test)

    print(f"\n{'='*60}")
    print("  STANDARD TEST RESULTS")
    print(f"{'='*60}")
    print(classification_report(y_test_labels, y_pred_labels))
    print(f"  Macro F1:          {f1_score(y_test_labels, y_pred_labels, average='macro'):.4f}")
    print(f"  Balanced Accuracy: {balanced_accuracy_score(y_test_labels, y_pred_labels):.4f}")
    print(f"  Standard Accuracy: {accuracy_score(y_test_labels, y_pred_labels):.4f}")

    # ------- BALANCED TEST EVALUATION -------
    print(f"\n{'='*60}")
    print("  BALANCED TEST EVALUATION")
    print(f"{'='*60}")

    # Sample up to 100 per class for balanced evaluation
    balanced_parts = []
    for cls in df["label"].unique():
        cls_df = df[df["label"] == cls]
        n = min(len(cls_df), 100)
        balanced_parts.append(cls_df.sample(n=n, random_state=42))
    balanced_df = pd.concat(balanced_parts).reset_index(drop=True)

    X_bal = balanced_df.drop(columns=["label", "label_encoded"])
    y_bal = balanced_df["label"]
    y_bal_enc = le.transform(y_bal)

    y_pred_bal = pipeline.predict(X_bal)
    y_pred_bal_labels = le.inverse_transform(y_pred_bal)

    print(classification_report(y_bal, y_pred_bal_labels))
    print(f"  Balanced Accuracy (True): {balanced_accuracy_score(y_bal, y_pred_bal_labels):.4f}")

    # ------- CROSS VALIDATION -------
    print(f"\n{'='*60}")
    print("  CROSS VALIDATION (3-Fold Stratified)")
    print(f"{'='*60}")

    # Filter small classes for CV safety
    min_samples = 20
    class_counts = df["label"].value_counts()
    valid_classes = class_counts[class_counts >= min_samples].index
    cv_df = df[df["label"].isin(valid_classes)].copy()

    X_cv = cv_df.drop(columns=["label", "label_encoded"])
    y_cv = cv_df["label"]

    le_cv = LabelEncoder()
    y_cv_encoded = le_cv.fit_transform(y_cv)

    min_cv_class = pd.Series(y_cv_encoded).value_counts().min()
    safe_k_cv = min(5, max(1, min_cv_class - 1))

    cv_smote = BorderlineSMOTE(k_neighbors=min(safe_k_cv, 1), random_state=42)

    cv_model = XGBClassifier(
        n_estimators=300,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.7,
        colsample_bytree=0.7,
        gamma=2,
        min_child_weight=5,
        reg_alpha=1,
        reg_lambda=2,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
    )

    cv_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("smote", cv_smote),
        ("model", cv_model),
    ])

    skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

    try:
        scores = cross_val_score(
            cv_pipeline,
            X_cv,
            y_cv_encoded,
            scoring="f1_macro",
            cv=skf,
            n_jobs=-1,
            error_score="raise",
        )
        print(f"  Fold Scores:   {scores}")
        print(f"  Mean Macro F1: {scores.mean():.4f}")
        print(f"  Std Dev:       {scores.std():.4f}")
    except Exception as e:
        print(f"  [!] Cross-validation failed: {e}")
        print("      (This is non-critical; the model is still trained and saved.)")

    return pipeline, le, feature_names


# ===========================================================
# STEP 12: SAVE ARTIFACTS
# ===========================================================
def save_artifacts(pipeline, le, feature_names):
    """Save the trained pipeline, label encoder, and feature list."""
    model_path = os.path.join(SCRIPT_DIR, "final_intrusion_model.pkl")
    encoder_path = os.path.join(SCRIPT_DIR, "label_encoder.pkl")
    features_path = os.path.join(SCRIPT_DIR, "feature_names.pkl")

    # Also save scaler and model separately for backward compatibility
    scaler_path = os.path.join(SCRIPT_DIR, "scaler.pkl")
    triage_model_path = os.path.join(SCRIPT_DIR, "triage_model_v2.pkl")

    # Save the full pipeline
    joblib.dump(pipeline, model_path)
    print(f"\n  [+] Pipeline saved:       {model_path}")

    # Save label encoder
    joblib.dump(le, encoder_path)
    print(f"  [+] Label encoder saved:  {encoder_path}")

    # Save feature names
    joblib.dump(feature_names, features_path)
    print(f"  [+] Feature names saved:  {features_path}")

    # Extract and save scaler + model separately
    scaler = pipeline.named_steps["scaler"]
    model = pipeline.named_steps["model"]

    joblib.dump(scaler, scaler_path)
    print(f"  [+] Scaler saved:         {scaler_path}")

    joblib.dump(model, triage_model_path)
    print(f"  [+] XGBoost model saved:  {triage_model_path}")

    print(f"\n  All artifacts saved to: {SCRIPT_DIR}")


# ===========================================================
# MAIN
# ===========================================================
def main():
    print("=" * 60)
    print("  SOAR2 MODEL TRAINING PIPELINE")
    print("  (Converted from soar2.ipynb)")
    print("=" * 60)

    # Parse args
    data_dir = None
    for i, arg in enumerate(sys.argv):
        if arg == "--data-dir" and i + 1 < len(sys.argv):
            data_dir = sys.argv[i + 1]

    # Load data
    print(f"\n{'='*60}")
    print("  STEP 1: LOADING DATA")
    print(f"{'='*60}")

    if data_dir:
        print(f"  Using custom CSV directory: {data_dir}")
        df = load_cicids_csvs(data_dir)
    else:
        print("  No --data-dir specified. Using KDD Cup 99 dataset (scikit-learn).")
        df = load_kdd_cup_99()

    # Clean
    print(f"\n{'='*60}")
    print("  STEP 2: CLEANING DATA")
    print(f"{'='*60}")
    df = clean_data(df)

    # Merge rare classes
    print(f"\n{'='*60}")
    print("  STEP 3: MERGING RARE CLASSES")
    print(f"{'='*60}")
    df = merge_rare_classes(df, threshold=50)

    # Show class distribution
    print(f"\n  Final class distribution:")
    for cls, count in df["label"].value_counts().items():
        print(f"    {cls}: {count}")

    # Train
    pipeline, le, feature_names = train_pipeline(df)

    # Save
    print(f"\n{'='*60}")
    print("  STEP 12: SAVING ARTIFACTS")
    print(f"{'='*60}")
    save_artifacts(pipeline, le, feature_names)

    print(f"\n{'='*60}")
    print("  ✅ TRAINING COMPLETE!")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
