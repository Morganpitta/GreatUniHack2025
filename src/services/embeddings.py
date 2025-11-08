## generate embeddings

from google import genai
from google.genai import types
from google.cloud import firestore
from google.cloud.firestore_v1.vector import Vector
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

OUTPUT_DIM=2048
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

    def embed_content(self, contents, task_type):
        try:
            return(self.client.models.embed_content(
            model=self.model_name,
            contents=contents,
            config=types.EmbedContentConfig(task_type=task_type, output_dimensionality=2048)))
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
            "embedding_field": Vector(embedding.embeddings[0].values), 
        }
        collection = self.db.collection(COLLECTION_NAME)
        collection.add(doc)

    def query_by_location(self, location):
        collection = self.db.collection(COLLECTION_NAME)
        query = collection.where("location", "==", location)
        return query

    def find_similar(self, query, query_vector, limit: int = 10):
        nearest = query.find_nearest(vector_field="embedding_field", query_vector=query_vector, limit=limit, distance_measure="COSINE").get()
        return [doc.to_dict() for doc in nearest]

        nearest = collection.find_nearest


if __name__ == "__main__":

    texts = [
        "What is the meaning of life?",
        "What is the purpose of existence?",
        "How do I bake a cake?"]

    # Calculate cosine similarity. Higher scores = greater semantic similarity.

    embed = Embedder("gemini-embedding-001")
    embedding = embed.embed_content(texts, "RETRIEVAL_DOCUMENT")
    store = Firestore(cred)
    store.save_to_collection("mars", embedding)
    print(store.query_by_location("mars"))

    db = firestore.client()
    user_query = "What is the surface of Mars like?" 

    embedding_response = embed.embed_content(user_query, "RETRIEVAL_QUERY")
    
    similar = store.find_similar(db.collection(COLLECTION_NAME), embedding_response, 10)
    print(similar)



