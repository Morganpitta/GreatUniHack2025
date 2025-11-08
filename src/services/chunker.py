## Use gemini to analyze outbound messages and generate recommendations for planets based on their culture
## Multimodal inputs
## Use Gemini for large context window
## RAG retrival augmented generation
## Vertex AI matching engine
## use semantic chunking

from llama_index.core.node_parser import (
    SentenceSplitter,
    SemanticSplitterNodeParser,
)
from llama_index.embeddings.gemini import GeminiEmbedding
from llama_index.core import SimpleDirectoryReader, Document

# Chunker splits text based on semantic similarity to preserve context
class Chunker:
    def __init__(self, embeddings_model: GeminiEmbedding):
        self.splitter = SemanticSplitterNodeParser(buffer_size=1, breakpoint_percentile_threshold=95, embed_model=embeddings_model)
        self.base_splitter = SentenceSplitter(chunk_size=512) 

    def chunk(self, documents: list[Document]):
        nodes = self.splitter.get_nodes_from_documents(documents)
        print(nodes[1].get_content())
        # return chunks as documents

    # embed_model = GeminiEmbedding()
    # chunker = Chunker(embeddings_model=embed_model)
    # documents = SimpleDirectoryReader(input_files=["./test.txt"]).load_data()
    # chunker.chunk(documents)
