from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
import pandas as pd
import shap
import warnings
from feature_extractor import extract_url_features
from datetime import datetime

warnings.filterwarnings("ignore")
app = Flask(__name__)
model = None
scaler = None
explainer = None
feature_names = None

def load_models():
    global model, scaler, explainer, feature_names
    try:
        print("Loading trained model and scaler...")
        model = joblib.load('best_phishing_model.pkl')
        scaler = joblib.load('feature_scaler.pkl')
        sample_url = "https://example.com"
        sample_features = extract_url_features(sample_url)
        feature_names = list(sample_features.keys())
        X_sample = pd.DataFrame([sample_features])
        X_sample_scaled = scaler.transform(X_sample)
        explainer = shap.TreeExplainer(model)
        print("Models loaded successfully!")
        return True
    except Exception as e:
        print(f"Error loading models: {e}")
        return False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/health', methods=['GET'])
def health_check():
    if model is not None and scaler is not None and explainer is not None:
        return jsonify({
            'status': 'healthy',
            'model_loaded': True,
            'message': 'AI Phishing Detection System is ready'
        })
    else:
        return jsonify({
            'status': 'unhealthy',
            'model_loaded': False,
            'message': 'Models not loaded'
        }), 500

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        real_time = data.get('real_time', False)

        if not url:
            return jsonify({'error': 'No URL provided', 'message': 'Please provide a URL'}), 400

        features = extract_url_features(url)
        X = pd.DataFrame([features])
        X_scaled = scaler.transform(X)
        prediction = model.predict(X_scaled)[0]
        prediction_proba = model.predict_proba(X_scaled)[0]

        shap_values = explainer.shap_values(X_scaled)
        # SHAP handling: Pick correct structure for model output
        if isinstance(shap_values, list) and len(shap_values) == 2:
            shap_vals = shap_values[1][0]
        else:
            shap_vals = shap_values[0][0]

        feature_importance = []
        for i, feature_name in enumerate(feature_names):
            importance = float(shap_vals[i])
            feature_importance.append({
                'feature': feature_name.replace('_', ' ').title(),
                'value': float(X.iloc[0, i]),
                'shap_value': importance,
                'impact': 'increases risk' if importance > 0 else 'decreases risk'
            })
        feature_importance.sort(key=lambda x: abs(x['shap_value']), reverse=True)
        top_risk_factors = feature_importance[:5]

        # Generate report/explanation fields
        reasons = [
            "Suspicious keywords: " + ', '.join([f['feature'] for f in top_risk_factors if f['impact'] == 'increases risk']),
            "Shortened link detected" if features['is_shortened'] else "",
            "Domain age < 1 month" if features['domain_age_days'] < 30 else "",
            "Hyphens in domain/subdomain" if features['hyphen_count'] > 0 else ""
        ]
        anatomy = {
            "ssl": "Present" if features["has_https"] else "Missing",
            "ip_in_domain": bool(features["has_ip"]),
            "shortened_url": bool(features["is_shortened"])
        }
        advice = "Never enter credentials. Use trusted sites. Report suspicious domains."
        confidence = max(prediction_proba) * 100
        result = "High Phishing Risk" if prediction == 1 and confidence > 80 else \
                 "Moderate Phishing Risk" if prediction == 1 and confidence > 60 else \
                 "Low Phishing Risk" if prediction == 1 else "Legitimate URL"
        risk_level = "high" if prediction == 1 and confidence > 80 else \
                     "medium" if prediction == 1 and confidence > 60 else \
                     "low" if prediction == 1 else "safe"
        response = {
            'result': result,
            'risk_level': risk_level,
            'confidence': round(confidence, 2),
            'prediction': int(prediction),
            'probability_phishing': round(float(prediction_proba[1]) * 100, 2),
            'probability_legitimate': round(float(prediction_proba[0]) * 100, 2),
            'top_risk_factors': top_risk_factors,
            'all_features': features,
            'url_analyzed': url,
            'report_reasons': [r for r in reasons if r],
            'phishing_anatomy': anatomy,
            'advice': advice,
            'scan_timestamp': datetime.now().isoformat()
        }
        return jsonify(response)
    except Exception as e:
        print(f"Error in prediction: {e}")
        return jsonify({'error': 'Prediction failed', 'message': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    if load_models():
        print("Starting AI Phishing Detection System...")
        print("Access the application at: http://localhost:5000")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("Failed to load models. Please run train_model.py first.")
