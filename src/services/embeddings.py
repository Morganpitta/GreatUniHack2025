## generate embeddings

from google import genai
from google.genai import types
from google.cloud.firestore_v1.vector import Vector
from google.cloud.firestore_v1.base_vector_query import DistanceMeasure
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

OUTPUT_DIM=768
COLLECTION_NAME='messages'

cred = credentials.Certificate('/home/george/GreatUniHack/GreatUniHack2025/src/services/space-mouse-4803e-firebase-adminsdk-fbsvc-98226ecde3.json')

firebase_admin.initialize_app(cred)
client = genai.Client()

# group users by their location

# location, vector


class Embedder:
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.client = genai.Client()

    def embed_content(self, contents, task_type) -> list[float]:
        try:
            response = self.client.models.embed_content(
            model=self.model_name,
            contents=contents,
            config=types.EmbedContentConfig(task_type=task_type, output_dimensionality=OUTPUT_DIM))
            return response.embeddings[0].values
        except:
            raise Exception("Error embedding content")

class Firestore:
    def __init__(self, credential):
        self.credential = credential
        # call once
        # firebase_admin.initialize_app(self.credential)
        self.db = firestore.client()
    
    def save_to_collection(self, collection_name, embedding):
        doc = {
            "location": collection_name,
            "embedding_field": Vector(embedding), 
        }
        collection = self.db.collection(COLLECTION_NAME)
        collection.add(doc)

    def query_by_location(self, location):
        collection = self.db.collection(COLLECTION_NAME)
        query = collection.where("location", "==", location)
        return query

    def find_similar(self, query, query_vector, limit: int = 10):
        nearest = query.find_nearest(vector_field="embedding_field", query_vector=query_vector, limit=limit, distance_measure=DistanceMeasure.COSINE).get()
        return [doc.to_dict() for doc in nearest]

        nearest = collection.find_nearest


if __name__ == "__main__":

    texts = ["Mars is a really beautiful planet", "Mars has lots of trees on it's surface"]

    embed = Embedder("gemini-embedding-001")
    embedding = embed.embed_content(texts, "RETRIEVAL_DOCUMENT")
    store = Firestore(cred)
    store.save_to_collection("mars", embedding)
    print(store.query_by_location("mars"))

    db = firestore.client()
    user_query = "What is the surface of Mars like?" 

    embedding_response = embed.embed_content(user_query, "RETRIEVAL_QUERY")
    
    similar = store.find_similar(db.collection(COLLECTION_NAME), embedding_response, 10)

    retrieved_context = "\n".join(doc.get("text_content","") for doc in similar)
    prompt = f"""
Answer the following question based only on the provided context.

Context:
{retrieved_context}

Question:
{user_query}
"""
    final_response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents=prompt,
    )
    print(final_response.text)
    
