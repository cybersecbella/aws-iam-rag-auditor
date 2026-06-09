"""
retriever.py — Load FAISS store and retrieve relevant chunks
"""
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings

VECTORSTORE_PATH = "vectorstore/aws_iam"


def load_retriever(k: int = 6):
    """
    Load the FAISS vector store and return a retriever.
    k = number of chunks to retrieve per query.
    """
    embeddings = HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        model_kwargs={"device": "cpu"},
    )
    vectorstore = FAISS.load_local(
        VECTORSTORE_PATH,
        embeddings,
        allow_dangerous_deserialization=True,
    )
    retriever = vectorstore.as_retriever(
        search_type="mmr",           # Maximum Marginal Relevance — diverse results
        search_kwargs={"k": k, "fetch_k": 20},
    )
    return retriever


def retrieve(query: str, k: int = 6) -> list:
    """Retrieve top-k relevant chunks for a query."""
    retriever = load_retriever(k=k)
    docs = retriever.invoke(query)
    return docs