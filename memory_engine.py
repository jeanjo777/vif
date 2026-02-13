
import os
import sys

# Disable ChromaDB telemetry completely BEFORE importing chromadb
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["CHROMA_TELEMETRY"] = "False"
os.environ["POSTHOG_DISABLED"] = "True"

# Mock posthog to prevent telemetry errors
class MockPosthog:
    def capture(self, *args, **kwargs): pass
    def identify(self, *args, **kwargs): pass
    def flush(self, *args, **kwargs): pass
    def shutdown(self, *args, **kwargs): pass

sys.modules['posthog'] = MockPosthog()

import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions
from cryptography.fernet import Fernet
import uuid

class MemoryEngine:
    def __init__(self, persistence_path="secure_storage/memory_db", encryption_key=None):
        # Create client with telemetry disabled
        settings = Settings(
            anonymized_telemetry=False,
            allow_reset=True
        )
        self.client = chromadb.PersistentClient(path=persistence_path, settings=settings)
        self.cipher = Fernet(encryption_key) if encryption_key else None
        
        self.embedding_fn = embedding_functions.DefaultEmbeddingFunction()
        
        self.collection = self.client.get_or_create_collection(
            name="doudou_memory",
            embedding_function=self.embedding_fn
        )
        print(f"🧠 Encrypted MemoryEngine initialized at {persistence_path}")

    def add(self, text, metadata=None, id=None):
        if not text: return
        try:
            # Générer un ID unique si non fourni
            if not id:
                id = str(uuid.uuid4())
            
            # 1. Generate Vector from PLAIN TEXT
            vectors = self.embedding_fn([text])
            
            # 2. Encrypt Content if cipher exists
            content_to_store = text
            if self.cipher:
                content_to_store = self.cipher.encrypt(text.encode()).decode()
                
            # 3. Store Encrypted Content + Plain Vector
            self.collection.add(
                embeddings=vectors,
                documents=[content_to_store],
                metadatas=[metadata] if metadata else None,
                ids=[id]
            )
            # print(f"🧠 Remembered: {text[:30]}...")
        except Exception as e:
            print(f"❌ Memory Add Error: {e}")

    def query(self, text, n_results=3):
        try:
            results = self.collection.query(
                query_texts=[text],
                n_results=n_results
            )
            # Format simple : liste de strings
            if results and results['documents']:
                raw_docs = results['documents'][0]
                decrypted_docs = []
                for doc in raw_docs:
                    if self.cipher:
                        try:
                            decrypted = self.cipher.decrypt(doc.encode()).decode()
                            decrypted_docs.append(decrypted)
                        except: 
                            decrypted_docs.append(doc) # Fallback if not encrypted or valid
                    else:
                        decrypted_docs.append(doc)
                return decrypted_docs
            return []
        except Exception as e:
            print(f"❌ Memory Query Error: {e}")
            return []

    def count(self):
        return self.collection.count()
