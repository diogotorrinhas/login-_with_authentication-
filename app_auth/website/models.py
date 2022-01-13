from database.database import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True)
    password = db.Column(db.String(256))
    first_name = db.Column(db.String(128))
    last_name = db.Column(db.String(128))
    reservations = db.relationship('Reservation')
        
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True) # Products are unique
    cost = db.Column(db.Float(asdecimal=True, decimal_return_scale=2)) #TODO: verificar os argumentos --> https://docs.sqlalchemy.org/en/14/core/type_basics.html#sqlalchemy.types.Float
    availability = db.Column(db.Boolean)
    quantity = db.Column(db.Integer)
    image_url = db.Column(db.String(128))
    description = db.Column(db.String(256))
    reservations = db.relationship('Reservation')

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer)
    date = db.Column(db.DateTime(timezone=True), default=func.now())

