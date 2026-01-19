from google import genai
from PIL import Image

#Loading an image
try:
    img = Image.Open("Your_Image.jpg")
except FileNotFoundError:

    print("Error: Image file not found. Please provide an Image.")
    exit()

#Multimodal prompts
prompt_parts = [
    img, #Image part
    "What is the primary objective of the Image"

]

#Generate contents with multimodal images
response_multimodal = client.models.generate_content(
    model = 'gemini-2.5-flash'
    content = prompt_parts
)

#Print the Multimodal repsonse
print("\n----Multimodal Response----")
print(response_multimodal.text)
print("-----------------------------")

