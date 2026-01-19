import os
import json
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
import time

app = Flask(__name__)
# Enable CORS to allow the HTML client (running on a different origin) to connect.
CORS(app) 

# --- Configuration ---
# NOTE: Using a model that supports Google Search Grounding
MODEL_NAME = 'gemini-2.5-flash-preview-09-2025'
# The API key is left empty as the environment will inject it if available.
API_KEY = os.environ.get('GEMINI_API_KEY') or "" 
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL_NAME}:generateContent?key={API_KEY}"

# --- Helper Function for API Calls with Backoff ---

def make_api_call_with_backoff(payload, max_retries=5):
    """Handles API call with exponential backoff for transient errors."""
    for attempt in range(max_retries):
        try:
            response = requests.post(
                API_URL, 
                headers={'Content-Type': 'application/json'},
                data=json.dumps(payload)
            )
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.HTTPError as e:
            # Check for rate limiting or other transient errors (e.g., 429)
            if response.status_code in [429, 503] and attempt < max_retries - 1:
                sleep_time = 2 ** attempt
                print(f"Rate limit or server error ({response.status_code}). Retrying in {sleep_time}s...")
                time.sleep(sleep_time)
            else:
                # Re-raise the exception if it's not a transient error or max retries reached
                raise e
        except requests.exceptions.RequestException as e:
            # Handle non-HTTP errors like connection errors
            if attempt < max_retries - 1:
                sleep_time = 2 ** attempt
                print(f"Connection error: {e}. Retrying in {sleep_time}s...")
                time.sleep(sleep_time)
            else:
                raise e
    raise Exception("Max retries reached without successful API response.")

@app.route('/generate-ai-response', methods=['POST'])
def generate_ai_response():
    """
    Receives a prompt from the front-end and calls the Gemini API
    with Google Search Grounding enabled.
    """
    if not API_KEY:
        return jsonify({
            'message': 'Server error: GEMINI_API_KEY is not set.'
        }), 500

    try:
        data = request.get_json()
        prompt = data.get('prompt', '')

        if not prompt:
            return jsonify({'message': 'No prompt provided.'}), 400

        # Construct the payload for the Gemini API call
        payload = {
            # Note: We are only sending the current prompt, not full chat history
            "contents": [{ "parts": [{ "text": prompt }] }],

            # Enable Google Search grounding
            "tools": [{ "google_search": {} }],

            # System instructions are optional, but useful for persona
            "systemInstruction": {
                "parts": [{ "text": "You are a helpful, concise, and knowledgeable AI assistant called Chamsi. Your responses must be grounded in real-time information when possible." }]
            },
        }

        result = make_api_call_with_backoff(payload)
        
        candidate = result.get('candidates', [{}])[0]
        generated_text = candidate.get('content', {}).get('parts', [{}])[0].get('text', 'No response text found.')

        # Extract grounding sources (citations)
        sources = []
        grounding_metadata = candidate.get('groundingMetadata')
        if grounding_metadata and grounding_metadata.get('groundingAttributions'):
            sources = [
                {
                    'uri': attribution.get('web', {}).get('uri'),
                    'title': attribution.get('web', {}).get('title'),
                }
                for attribution in grounding_metadata['groundingAttributions']
                if attribution.get('web', {}).get('uri') and attribution.get('web', {}).get('title')
            ]
        
        return jsonify({ 
            'message': 'AI generation successful.', 
            'response': generated_text,
            'sources': sources
        }), 200

    except Exception as e:
        print(f"Gemini API Error: {e}")
        return jsonify({'message': f'AI processing error: {e}. Please ensure the GEMINI_API_KEY is set and valid.'}), 500

if __name__ == '__main__':
    print("--- Python Flask AI Server Setup ---")
    print("NOTE: You must start this server separately before running the HTML client.")
    print("The client will attempt to connect to http://localhost:3000.")
    app.run(port=3000, debug=True)