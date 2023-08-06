from app import db
from sqlalchemy_serializer import SerializerMixin
from datetime import datetime

class Message(db.Model, SerializerMixin):
    __tablename__ = "message"
    
    id = db.Column(db.Integer, primary_key=True)
    messages = db.Column(db.String(1000))
    privacy = db.Column(db.String(20))
    date_created = db.Column(db.DateTime)
    date_update = db.Column(db.DateTime)
    
    def __init__(self, privacy, messages):
        self.messages = messages
        self.privacy = privacy
        self.date_created = datetime.now()
        self.date_update = datetime.now()

    def update(self, privacy, messages):
        self.messages = messages
        self.privacy = privacy
        self.date_update = datetime.now()
    