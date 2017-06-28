#/usr/bin/env python
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import hashlib


Base = declarative_base()

# Md5 hasher for user login


def md5Hasher(password):
    return hashlib.md5(password.encode("utf")).hexdigest()

# Create User


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(54), nullable=False)
    password = Column(String(100), nullable=False)
    avatar = Column(String(250), nullable=False)


# Create Category
class Category(Base):
    __tablename__ = 'category'
    cat_id = Column(Integer, primary_key=True)
    cat_name = Column(String(75), nullable=False)
    cat_u = Column(Integer)

    @property
    def serialize(self):
        return {
            'cat_id': self.cat_id,
            'cat_name': self.cat_name,
        }

# # Create Item


class Item(Base):
    __tablename__ = 'items'
    item_id = Column(Integer, primary_key=True)
    item_name = Column(String, nullable=False)
    item_description = Column(String, nullable=False)
    item_img = Column(String, nullable=False)
    item_cat = Column(String, ForeignKey('category.cat_id'))
    item_u = Column(Integer, ForeignKey('users.id'))


    @property
    def serialize(self):
        return {
            'item_id': self.item_id,
            'item_name': self.item_name,
            'item_description': self.item_description,
            'item_img': self.item_img,
            'item_cat': self.item_cat,
        }
engine = create_engine('sqlite:///catalogitem.db')

Base.metadata.create_all(engine)
