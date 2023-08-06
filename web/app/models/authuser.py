from flask_login import UserMixin
from sqlalchemy_serializer import SerializerMixin
from .moods import Moody
from .message import Message

from app import db

class AuthUser(db.Model, UserMixin, SerializerMixin):
    __tablename__ = "auth_users"
    # primary keys are required by SQLAlchemy
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    username = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(100))
    avatar_url = db.Column(db.String(100))
    tel = db.Column(db.String(20))
    birthday = db.Column(db.Date)
    gender = db.Column(db.String(10))
    age = db.Column(db.Integer)

    def __init__(self, email, username, name, password, avatar_url, tel=None, birthday=None, gender=None, age=None):
        self.email = email
        self.username = username
        self.name = name
        self.password = password
        self.avatar_url = avatar_url
        self.tel = tel
        self.birthday = birthday
        self.gender = gender
        self.age = age

    def update(self, email=None, username=None, name=None, avatar_url=None, tel=None, birthday=None, gender=None, age=None):
        if email is not None:
            self.email = email
        if username is not None:
            self.username = username
        if name is not None:
            self.name = name
        if avatar_url is not None:
            self.avatar_url = avatar_url
        if tel is not None:
            self.tel = tel
        if birthday is not None:
            self.birthday = birthday
        if gender is not None:
            self.gender = gender
        if age is not None:
            self.age = age

        
class PrivateMood(Moody, UserMixin, SerializerMixin):
    owner_id = db.Column(db.Integer, db.ForeignKey('auth_users.id'))

    def __init__(self, sleep, meditation, mind, boring, social, sum_mood, owner_id):
        super().__init__( sleep, meditation, mind, boring, social, sum_mood)
        self.owner_id = owner_id


class PrivateMessage(Message, UserMixin, SerializerMixin):
    owner_id = db.Column(db.Integer, db.ForeignKey('auth_users.id'))

    def __init__(self,  privacy, messages, owner_id):
        super().__init__(privacy, messages)
        self.owner_id = owner_id