import os
import asyncio
import logging
import google.generativeai as genai
from datetime import datetime
from pydantic import BaseModel, Field
import uuid

logger = logging.getLogger(__name__)

class ChatMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    message: str
    response: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ChatRequest(BaseModel):
    message: str
    user_id: str

class UserMessage:
    def __init__(self, text: str):
        self.text = text

class LlmChat:
    def __init__(self, api_key: str, session_id: str, system_message: str):
        self.api_key = api_key or os.getenv('GEMINI_API_KEY', '')
        if not self.api_key:
            raise ValueError("Gemini API key is required")
        self.session_id = session_id
        self.system_message = system_message
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')

    def with_model(self, provider: str, model: str):
        return self

    async def send_message(self, message):
        try:
            chat = self.model.start_chat(history=[])
            full_prompt = f"{self.system_message}\n\nUser message: {message.text}"
            response = await asyncio.to_thread(chat.send_message, full_prompt)
            return response.text
        except Exception as e:
            logging.error(f"Gemini API error: {str(e)}")
            return f"[ERROR] Failed to get AI response: {str(e)}"

def get_system_message():
    """Get the system message for the AI chat."""
    return """You are AEGIS AI, a cybersecurity expert assistant. You help users understand security vulnerabilities, 
    provide recommendations for fixing security issues, and answer questions about web application security. 
    Be helpful, accurate, and provide actionable advice. Focus on practical security solutions."""

