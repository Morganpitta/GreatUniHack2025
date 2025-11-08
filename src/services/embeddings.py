## generate embeddings

from google import genai
from google.genai import types


client = genai.Client()

class Embedder:
    def __init__(self, embedding_size: int):
        self.client = genai.Client()

    def embed_content(self, contents: types.Content):
        try:
            return(self.client.models.embed_content(
            model="gemini-embedding-001",
            contents=contents))
        except:
            raise Exception("Error embedding content")

if __name__ == "__main__":
    texts = [
        "What is the meaning of life?",
        "What is the purpose of existence?",
        "How do I bake a cake?"]

    # Calculate cosine similarity. Higher scores = greater semantic similarity.

    embed = Embedder(0)
    print(embed.embed_content(texts))

