#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 29 22:28:04 2025
@author: jesus_delarosa_cyber
"""

import pandas as pd
import joblib
import numpy as np  # Required for scikit-learn/XGBoost internals
from sklearn.model_selection import train_test_split
from sklearn.ensemble import VotingClassifier, RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, roc_auc_score, 
                           classification_report, confusion_matrix)

def print_feature_importance(model, feature_names, model_name, top_n=15):
    """Print feature importance (NumPy 2.x compatible)"""
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        indices = np.argsort(importances, kind='stable')[-top_n:]  # Stable sort for NumPy 2.x
        
        importance_df = pd.DataFrame({
            'Feature': [feature_names[i] for i in indices],
            'Importance': importances[indices]
        }).sort_values('Importance', ascending=False)
        
        print(f"\nTop {top_n} Features for {model_name}:")
        print(importance_df.to_string(index=False))
    else:
        print(f"\nFeature importance not available for {model_name}")

def print_confusion_matrix(y_true, y_pred, model_name):
    """Confusion matrix with explicit NumPy 2.x float handling"""
    cm = confusion_matrix(y_true, y_pred)
    cm_normalized = cm.astype(np.float64) / cm.sum(axis=1).reshape(-1, 1)  # Explicit float64
    
    print(f"\nConfusion Matrix ({model_name}):")
    print("Actual\\Predicted  Safe  Malicious")
    print(f"Safe             {cm_normalized[0,0]:.2f}   {cm_normalized[0,1]:.2f}")
    print(f"Malicious        {cm_normalized[1,0]:.2f}   {cm_normalized[1,1]:.2f}")

def train_models(features_file):
    """Main training function (NumPy 2.x optimized)"""
    print("\nStarting model training...")
    try:
        # Load data (Pandas handles NumPy 2.x internally)
        df = pd.read_parquet(features_file)
        X = df.drop('label', axis=1)
        y = df['label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        print(f"\nDataset loaded: {len(X_train)} training, {len(X_test)} test samples")
        
        # Feature sets (Pure Python)
        full_features = X.columns.tolist()
        reduced_features = [col for col in full_features if col not in ['havingIP', 'hasPort']]
        
        def train_and_evaluate(features, name):
            """Train/evaluate with NumPy 2.x compatibility"""
            print(f"\n=== Training {name} Model ===")
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train[features])
            X_test_scaled = scaler.transform(X_test[features])
            
            # Models (internally use NumPy 2.x via scikit-learn)
            xgb = XGBClassifier(eval_metric='logloss', random_state=42)
            rf = RandomForestClassifier(n_estimators=100, random_state=42)
            lr = LogisticRegression(max_iter=1000, solver='lbfgs', random_state=42)
            
            model = VotingClassifier(
                estimators=[('xgb', xgb), ('rf', rf), ('lr', lr)],
                voting='soft'
            )
            model.fit(X_train_scaled, y_train)
            
            # Evaluate
            y_pred = model.predict(X_test_scaled)
            y_proba = model.predict_proba(X_test_scaled)[:, 1]  # NumPy array
            
            print("\nModel Performance:")
            print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
            print(f"AUC-ROC: {roc_auc_score(y_test, y_proba):.4f}")
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred))
            
            print_confusion_matrix(y_test, y_pred, name)
            
            # Feature importance (refit XGBoost)
            xgb.fit(X_train_scaled, y_train)
            print_feature_importance(xgb, features, name)
            
            return model, scaler
        
        # Train models
        full_model, full_scaler = train_and_evaluate(full_features, "Full Features")
        reduced_model, reduced_scaler = train_and_evaluate(reduced_features, "Reduced Features")
        
        # Ensemble (NumPy 2.x compatible operations)
        print("\n=== Evaluating Ensemble Model ===")
        prob_full = full_model.predict_proba(full_scaler.transform(X_test[full_features]))[:, 1]
        prob_reduced = reduced_model.predict_proba(reduced_scaler.transform(X_test[reduced_features]))[:, 1]
        
        # Use Python list comprehension for thresholding
        ensemble_prob = 0.7 * prob_full + 0.3 * prob_reduced
        ensemble_pred = [1 if prob > 0.5 else 0 for prob in ensemble_prob]  # Avoid np.int
        
        print("\nEnsemble Performance:")
        print(f"AUC-ROC: {roc_auc_score(y_test, ensemble_prob):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, ensemble_pred))
        print_confusion_matrix(y_test, ensemble_pred, "Ensemble Model")
        
        # Save models (joblib handles NumPy 2.x)
        joblib.dump(full_model, 'full_features_model.joblib')
        joblib.dump(reduced_model, 'reduced_features_model.joblib')
        joblib.dump({
            'scalers': (full_scaler, reduced_scaler),
            'feature_sets': (full_features, reduced_features),
            'weights': [0.7, 0.3],
            'metrics': {
                'full_model_auc': roc_auc_score(y_test, prob_full),
                'reduced_model_auc': roc_auc_score(y_test, prob_reduced),
                'ensemble_auc': roc_auc_score(y_test, ensemble_prob)
            }
        }, 'robust_ensemble.joblib')
        
        print("\nModels saved successfully:")
        print("- full_features_model.joblib")
        print("- reduced_features_model.joblib")
        print("- robust_ensemble.joblib")
        
    except Exception as e:
        print(f"\nTraining failed: {str(e)}")

if __name__ == "__main__":
    train_models('training_features.parquet')