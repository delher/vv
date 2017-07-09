from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from create_vv_db import Base, Producer, Variety, Wine, User, Report

engine = create_engine('sqlite:///vv.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()
# Create User
user1 = User(name = 'Del', email='del@herrings.net', authlevel = 2)
session.add(user1)
session.commit()

# Initialize Varieties
cabernet = Variety(name='Cabernet Sauvignon', color='red')
session.add(cabernet)

chardonnay = Variety(name='Chardonnay', color = 'white')
session.add(chardonnay)

malbec = Variety(name='Malbec', color = 'red')
session.add(malbec)

sauvblanc = Variety(name='Sauvignon Blanc', color = 'white')
session.add(sauvblanc)

shiraz = Variety(name='Shiraz', color = 'red')
session.add(shiraz)

syrah = Variety(name='Syrah', color = 'red')
session.add(syrah)

viognier = Variety(name='Viognier', color = 'white')
session.add(viognier)

whitezin = Variety(name='White Zinfandel', color = 'rosé')
session.add(whitezin)

sparkling = Variety(name='Sparkling', color = 'white')
session.add(sparkling)

red_blend = Variety(name='Red Blend', color = 'red')
session.add(red_blend)
session.commit()

white_blend = Variety(name='White Blend', color = 'white')
session.add(white_blend)
session.commit()


# First Producer
producer1 = Producer(name='Charles Shaw', nation='USA', region='California', added_by=user1)
session.add(producer1)

wine1 = Wine(producer=producer1, variety=chardonnay, vintage=2012, tag='Two-Buck Chuck', added_by=user1)
session.add(wine1)

wine2 = Wine(variety=shiraz, vintage=2012, tag='Two-Buck Chuck', producer=producer1, added_by=user1)
session.add(wine2)


wine3 = Wine(variety=cabernet, vintage=2012,tag='Two-Buck Chuck', producer=producer1, added_by=user1)
session.add(wine3)

# 2 Producer - Lindeman's
producer2 = Producer(name='Lindeman\'s', nation='Australia', region='Southeast', added_by=user1)
session.add(producer2)

wine4 = Wine(variety=chardonnay, vintage = 2015, tag ='Bin 65', producer = producer2, added_by=user1)
session.add(wine4)

wine5 = Wine(variety=cabernet, vintage = 2015, tag ='Bin 69', producer = producer2, added_by=user1)
session.add(wine5)

# 3 Producer - Alamos
producer3 = Producer(name='Alamos', nation ='Chile', region='Mendoza', added_by=user1)
session.add(producer3)

wine6 = Wine(variety=cabernet, vintage = 2014, tag = '', producer = producer3,
    imageURL='http://s3.amazonaws.com/alamoswinesus.com/assets/s3fs-public/cabernet.jpg', added_by=user1)
session.add(wine6)

wine7 = Wine(variety=malbec, vintage = 2015, tag = '', producer=producer3,
    imageURL='http://s3.amazonaws.com/alamoswinesus.com/assets/s3fs-public/malbec.jpg', added_by=user1)
session.add(wine7)

# 4 Producer - Cook's
producer4 = Producer(name='Cook\'s', nation ='USA', region ='California', added_by=user1)
session.add(producer4)

wine8 = Wine(variety = sparkling, vintage = 2016, tag = 'extra dry | champagne', producer=producer4,
    imageURL='http://www.cookschampagne.com/images/cooks-extra-dry-bt-lg.png', added_by=user1)
session.add(wine8)

session.commit()

print ('Producers & wines added to database.')