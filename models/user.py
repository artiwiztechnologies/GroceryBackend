from db import db
import datetime

class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200))
    password = db.Column(db.String(80))
    status  = db.Column(db.Integer ) #not verified is 1 and 2 is verified and 3 is admin
    phonenumber = db.Column(db.String(80))
    dateTime = db.Column(db.DateTime, default=datetime.datetime.now())

    def __init__(self, email,password,status,phonenumber):
        self.email = email
        self.password = password
        self.status = status
        self.phonenumber = phonenumber


    def json(self):
        return {
            'id': self.id,
            'email': self.email
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, email):
        return cls.query.filter_by(email=email).first()

    @classmethod
    def find_by_phonenumber(cls, phonenumber):
        return cls.query.filter_by(phonenumber=phonenumber).first()

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()
