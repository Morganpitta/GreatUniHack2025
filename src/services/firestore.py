## Interact with Firestore

from firebase_admin import firestore
from google.cloud.firestore_v1.vector import Vector
from google.cloud.firestore_v1.base_vector_query import DistanceMeasure


COLLECTION_NAME="messages"

class Firestore:
    """
    Class for integrating Gemini AI with Firestore
    """
    def __init__(self):
        self.db = firestore.client()
    
    def save_to_collection(self, collection_name, embedding, texts):
        """
        Save vector embedding to Firestore
        """
        doc = {
            "location": collection_name,
            "embedding_field": Vector(embedding), 
            "text_content": texts
        }
        collection = self.db.collection(COLLECTION_NAME)
        collection.add(doc)

    def query_by_location(self, location, query_vector):
        """
        Generate context for Gemini from messages by location
        query_vector is the question asked by the user
        """
        collection = self.db.collection(COLLECTION_NAME)

        # build query filter by location
        query = collection.where("location", "==", location)

        # compare using cosine distance measure
        nearest = query.find_nearest(vector_field="embedding_field", query_vector=query_vector, limit=20, distance_measure=DistanceMeasure.COSINE).get()
        return [doc.to_dict() for doc in nearest]
    
    def generate_prompt(self, gemini, location) -> str:
        """
        TODO: Split this
        Method for generating a full prompt for recommendations on planets
        """
        query = f"Which landmarks can I visit in {location}?"
        # Create query embedding
        embedding_response = gemini.embed_content(query, "RETRIEVAL_QUERY")
        # Find similar from outbound messages of the location
        similar = self.query_by_location(location, embedding_response)
        retrieved_context = "\n".join("".join(doc.get("text_content","")) for doc in similar)
        prompt = f"""
    You are a tour guide with boundless facts and knowledge about the history of famous landmarks.
    You are reading about famous landmarks of interest from people who live in {location}
    Answer the following question based only on the provided context.
    If there is no context, only apologise and end the prompt. Nobody can know you are AI.

    Context:
    {retrieved_context}

    Question:
    {query}
    """
        return prompt