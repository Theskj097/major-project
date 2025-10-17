import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
import xgboost as xgb
import joblib
import warnings
warnings.filterwarnings("ignore")
from feature_extractor import extract_url_features

def main():
    print("=== AI Phishing Detection System - Model Training ===\n")
    df = pd.read_csv('phishing_urls_dataset.csv')
    print(f"Loaded {len(df)} URLs ({len(df[df['Label'] == 'bad'])} phishing, {len(df[df['Label'] == 'good'])} legitimate)\n")
    features_list, labels = [], []
    for idx, row in df.iterrows():
        url = row['URL']
        label = row['Label']
        try:
            features = extract_url_features(url)
            features_list.append(features)
            labels.append(1 if label == 'bad' else 0)
        except Exception as e:
            print(f"Error processing URL: {e}")
            continue
    X = pd.DataFrame(features_list)
    y = np.array(labels)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    models = {
        'RandomForest': {
            'model': RandomForestClassifier(random_state=42),
            'params': {
                'n_estimators': [50, 100, 200],
                'max_depth': [5, 10, 15, None],
                'min_samples_split': [2, 5],
                'min_samples_leaf': [1, 2]
            }
        },
        'XGBoost': {
            'model': xgb.XGBClassifier(random_state=42, eval_metric='logloss'),
            'params': {
                'n_estimators': [50, 100, 200],
                'max_depth': [3, 5, 7],
                'learning_rate': [0.1, 0.2],
                'subsample': [0.8, 1.0]
            }
        }
    }
    best_model, best_score, best_model_name = None, 0, ""
    for model_name, model_config in models.items():
        grid_search = GridSearchCV(model_config['model'], model_config['params'], cv=5, scoring='f1', n_jobs=-1, verbose=0)
        grid_search.fit(X_train_scaled, y_train)
        score = grid_search.best_score_
        print(f"{model_name} - Best CV F1 Score: {score:.4f}")
        print(f"{model_name} - Best Parameters: {grid_search.best_params_}")
        if score > best_score:
            best_score, best_model, best_model_name = score, grid_search.best_estimator_, model_name
    print(f"\nBest model: {best_model_name} with F1 Score: {best_score:.4f}")
    y_pred = best_model.predict(X_test_scaled)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    if hasattr(best_model, 'feature_importances_'):
        print("\nTop 10 Most Important Features:")
        print(pd.DataFrame({'feature': X.columns, 'importance': best_model.feature_importances_}).sort_values('importance', ascending=False).head(10))
    joblib.dump(best_model, 'best_phishing_model.pkl')
    joblib.dump(scaler, 'feature_scaler.pkl')
    print("\n=== Training Complete ===")
    print(f"Best model saved as: best_phishing_model.pkl")
    print(f"Feature scaler saved as: feature_scaler.pkl")
    print(f"Model type: {best_model_name}")
    print(f"Test F1 Score: {f1_score(y_test, y_pred):.4f}")

if __name__ == "__main__":
    main()
