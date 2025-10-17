import re
import math
from urllib.parse import urlparse, parse_qs
import whois
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")

def extract_url_features(url):
    """
    Extract comprehensive features from a URL for phishing detection.

    Args:
        url (str): The URL to analyze

    Returns:
        dict: Dictionary containing extracted features
    """
    features = {}

    try:
        # Parse the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path
        query = parsed_url.query

        # === LEXICAL FEATURES ===
        features['url_length'] = len(url)
        features['dot_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')
        features['slash_count'] = url.count('/')
        features['digit_count'] = sum(c.isdigit() for c in url)

        # Subdomain count (number of dots in domain minus 1)
        features['subdomain_count'] = max(0, domain.count('.') - 1) if domain else 0

        # Query parameters count
        features['query_params_count'] = len(parse_qs(query)) if query else 0

        # URL entropy (measure of randomness)
        def calculate_entropy(text):
            if not text:
                return 0
            prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
            entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
            return entropy

        features['url_entropy'] = calculate_entropy(url)

        # Digit to letter ratio
        letters = sum(c.isalpha() for c in url)
        digits = sum(c.isdigit() for c in url)
        features['digit_to_letter_ratio'] = digits / max(letters, 1)

        # === KEYWORD FEATURES ===
        suspicious_keywords = [
            'login', 'secure', 'bank', 'account', 'update', 'verify',
            'signin', 'password', 'confirm', 'suspend', 'locked',
            'urgent', 'immediate', 'expire', 'renewal', 'security',
            'alert', 'warning', 'notice', 'action', 'required'
        ]

        url_lower = url.lower()
        for keyword in suspicious_keywords:
            features[f'has_{keyword}'] = 1 if keyword in url_lower else 0

        # === DOMAIN-BASED FEATURES ===
        features['domain_length'] = len(domain) if domain else 0

        # WHOIS-based features (Note: These lookups can be slow)
        try:
            if domain and not re.match(r'^\\d+\\.\\d+\\.\\d+\\.\\d+', domain):
                domain_info = whois.whois(domain)
                # Domain age in days
                if domain_info.creation_date:
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    age_days = (datetime.now() - creation_date).days
                    features['domain_age_days'] = max(0, age_days)
                else:
                    features['domain_age_days'] = 0
                # Domain lifespan (expiration - creation)
                if domain_info.creation_date and domain_info.expiration_date:
                    creation = domain_info.creation_date
                    expiration = domain_info.expiration_date
                    if isinstance(creation, list):
                        creation = creation[0]
                    if isinstance(expiration, list):
                        expiration = expiration[0]
                    lifespan_days = (expiration - creation).days
                    features['domain_lifespan_days'] = max(0, lifespan_days)
                else:
                    features['domain_lifespan_days'] = 365  # Default to 1 year
            else:
                features['domain_age_days'] = 0
                features['domain_lifespan_days'] = 0
        except Exception:
            features['domain_age_days'] = 0
            features['domain_lifespan_days'] = 365

        # === OTHER FEATURES ===
        features['has_https'] = 1 if parsed_url.scheme == 'https' else 0
        features['has_ip'] = 1 if re.match(r'^\\d+\\.\\d+\\.\\d+\\.\\d+', domain) else 0
        features['has_at_symbol'] = 1 if '@' in url else 0

        shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
            'short.link', 'tiny.cc', 'lnkd.in', 'buff.ly', 'ift.tt'
        ]
        features['is_shortened'] = 1 if any(shortener in domain for shortener in shorteners) else 0

        return features

    except Exception as e:
        print(f"Error processing URL {url}: {str(e)}")
        return {key: 0 for key in [
            'url_length','dot_count','hyphen_count','slash_count',
            'digit_count','subdomain_count','query_params_count','url_entropy',
            'digit_to_letter_ratio','domain_length','domain_age_days',
            'domain_lifespan_days','has_https','has_ip','has_at_symbol',
            'is_shortened'
        ]}
