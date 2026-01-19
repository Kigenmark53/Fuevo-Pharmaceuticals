import os
from google import genai
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

#fetch api keys from .env file 
API_KEY = os.getenv("GEMINI_API_KEY")

# Initialize the Gemini client with the API key

try:
    client = genai.client(api_key=API_KEY)
    
except Exception as e:

    print(f"Error initializing Gemini Client: {e}")
    exit()

#Generating a simple text completion
prompt = "Explain the diesase with the highest mortality rate worldwide."

print(f"sending prompt: {prompt}")

# Send the prompt to the Gemini model and get the response
response = client.models.generate (
    model = "gemini-2.5-flash-preview-09-2025",
    prompt = genai.TextPrompt.from_text(prompt)
    contents = prompt
    )

#print the response
print("Response from Gemini Model:")
print(response.text)
print("--------------------------------")
