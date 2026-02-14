from flask import Flask, make_response, jsonify
import os

app = Flask(__name__)

# Toggle this env var to pass/fail the scan!
SECURE_MODE = os.environ.get('SECURE_MODE', 'FALSE').upper() == 'TRUE'

@app.route('/')
def home():
    data = {"message": "Hello from the Target App!", "secure_mode": SECURE_MODE}
    response = make_response(jsonify(data))

    if SECURE_MODE:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        
    return response

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)