from app import db
from sqlalchemy_serializer import SerializerMixin
from datetime import datetime

class Moody(db.Model, SerializerMixin):
    __tablename__ = "mood"
    
    id = db.Column(db.Integer, primary_key=True)
    sleep = db.Column(db.String(50))
    meditation = db.Column(db.String(50))
    mind = db.Column(db.String(20))
    boring = db.Column(db.String(20))
    social = db.Column(db.String(20))
    sum_mood = db.Column(db.String(20))
    date_created = db.Column(db.DateTime)
    date_update = db.Column(db.DateTime)
    
    def __init__(self, sleep, meditation, mind, boring, social, sum_mood):
        self.sleep = sleep
        self.meditation =  meditation 
        self.mind = mind
        self.boring = boring
        self.social =  social
        self.sum_mood = sum_mood
        self.date_created = datetime.now()
        self.date_update = datetime.now()
    