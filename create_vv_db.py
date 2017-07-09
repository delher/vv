import os
import sys
import random, string
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, Enum
from sqlalchemy.dialects.sqlite import DATE, DATETIME
Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    email = Column(String(100))
    authlevel = Column(Integer)

class Producer(Base):
    __tablename__ = 'producer'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    nation = Column(String(250))
    region = Column(String(250))
    added_by_id = Column(Integer, ForeignKey('user.id'))
    added_by = relationship(User, backref='producers')

class Variety(Base):
    __tablename__ = 'variety'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable = False)
    color = Column(String(50))

class Wine(Base):
    __tablename__ = 'wine'
    id = Column(Integer, primary_key=True)
    producer_id = Column(Integer, ForeignKey('producer.id'))
    producer = relationship(Producer, backref='wines')
    variety_id = Column(Integer, ForeignKey('variety.id'))
    variety = relationship(Variety, backref='wines')
    vintage = Column(Integer)
    tag = Column(String(250))
    imageURL = Column(String(250))
    added_by_id = Column(Integer, ForeignKey('user.id'))
    added_by = relationship(User, backref='wines')

    # serialize function allows export as a JSON object
    @property
    def serialize(self):
        return {
        'id': self.id,
        'variety_id': self.variety_id,
        'vintage': self.vintage,
        'tag': self.tag,
        'imageURL': self.imageURL
        }

class Report(Base):
    __tablename__ = 'report'
    id = Column(Integer, primary_key=True)
    wine_id = Column(Integer, ForeignKey('wine.id'))
    wine = relationship(Wine, backref = 'reports')
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User, backref = 'reports')
    user_report = Column(String, nullable=False)
    entry_time = Column(DATETIME, nullable=False)




engine = create_engine('sqlite:///vv.db')
Base.metadata.create_all(engine)