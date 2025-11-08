## Use gemini to analyze outbound messages and generate recommendations for planets based on their culture
## Multimodal inputs
## Use Gemini for large context window

from google import genai

# The client gets the API key from the environment variable `GEMINI_API_KEY`.
client = genai.Client()

response = client.models.generate_content(
    model="gemini-2.5-flash", contents="Explain how AI works in a few words"
)
print(response.text)
