from flask import Flask, render_template, request, redirect
from flask import url_for, flash, jsonify, session, make_response
from sqlalchemy import create_engine, asc, and_, func, exists
from sqlalchemy.orm import sessionmaker
from create_vv_db import Base, Producer, Variety, Wine, User, Report
import random, string, requests, datetime, httplib2, json
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from oauth2client import client
app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
engine = create_engine('sqlite:///vv.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
dbsession = DBSession()

# Route / - Show all wines grouped by producer
@app.route('/')
def showAllWines():
    allWines = dbsession.query(Wine, Variety, Producer).\
    join(Variety, Wine.variety_id == Variety.id).\
    join (Producer, Wine.producer_id == Producer.id)
    allProducers = dbsession.query(Producer).order_by(asc(Producer.name))
    return render_template('wines.html', allProducers = allProducers, allWines=allWines)

@app.route('/login')
def showLogin():
    stored_access_token = session.get('access_token')
    stored_gplus_id = session.get('gplus_id')
    if stored_access_token is not None and stored_gplus_id is not None:
        flash('You are already logged in.')
        return redirect(url_for('showAllWines'))

        return response
    state = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(32))
    session['state'] = state
    return render_template('login.html', STATE = state)


@app.route('/gconnect', methods = ['POST'])
def gconnect():
    # validate the state token
    if request.args.get('state') != session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = "application/json"
        return response
    # get authorization code
    code = request.data
    try:
        #upgrade the auth code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope = '')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)

    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response


    # check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    httpresponse = h.request(url,'GET')[1]
    result = json.loads(httpresponse.decode('utf-8'))

    # on error, abort and send 500 error
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    print('gplus_id = {}'.format(gplus_id))
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = session.get('access_token')
    stored_gplus_id = session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('You are already logged in.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    session['access_token'] = credentials.access_token
    session['gplus_id'] = gplus_id
    session['credentials'] = credentials.to_json()

    print(session.get('expiry'))

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    session['username'] = data['name']
    session['email'] = data['email']

    #see if user exists
    user_id = getUserId(session['email'])
    if not user_id:
        user_id = createUser(session)
        session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome! </h1>'
    flash("You are logged in using your email address: %s" % session['email'])
    return output

@app.route('/logout')
def gdisconnect():

    try:
        access_token = session['access_token']

    except:
        access_token = None

    if access_token is None:
        flash('You are not logged in.')
        return redirect(url_for('showAllWines'))

    try:
        credentials = client.OAuth2Credentials.from_json(session['credentials'])
        credentials.revoke(httplib2.Http())
    except:
        flash('Login Expired.')

    # in either case, reset the session and return the main page.
    session.clear()
    flash('Your login information has been cleared.')
    return redirect(url_for('showAllWines'))


# Producer CRUD Operations
# 1 - Producer CREATE (Add)
@app.route('/add/producer/', methods = ['GET', 'POST'])
def addProducer():

    if 'username' not in session:
            flash('You must be logged in to add a producer.')
            return redirect(url_for('showLogin'))

    if request.method == 'GET':
        return render_template('add_producer.html')

    if request.method == 'POST':
        newProducer = request.form['name']
        newRegion = request.form['region']
        newCountry = request.form['country']
    # check whether this producer exists in the db already:

    producer_id = dbsession.query(Producer.id).filter(func.lower(Producer.name) == func.lower(newProducer)).scalar()
    if producer_id:
        flash('{} is already listed in the database:'.format(newProducer))
        return redirect(url_for('viewProducer', producer_id = producer_id))

    # find the user's id by email lookup
    user_id = getUserId(session.get('email'))

    # build a new Producer object
    producer = Producer(name = newProducer, region = newRegion, nation = newCountry,\
        added_by_id = user_id)
    # add the new producer to the db and commit.
    dbsession.add(producer)
    dbsession.commit()

    flash('New producer {} has been added!'.format(producer.name))
    return redirect(url_for('viewProducer', producer_id = producer.id))

# 2 - Producer READ (View) - Show all wines for a single producer
@app.route('/view/producer/<int:producer_id>/')
def viewProducer(producer_id):
    producer = check_producer_ID(producer_id)
    if producer == None:
        flash('Producer ID not valid.')
        return redirect(url_for('showAllWines'))
    winelist = dbsession.query(Wine, Variety).join(Variety, Wine.variety_id == Variety.id).filter(Wine.producer_id == producer_id)
    user = dbsession.query(User).filter_by(id = producer.added_by_id).one()
    editFlag = (user.email == session.get('email'))


    return render_template('view_producer.html', producer = producer, winelist = winelist, editFlag = editFlag)

# 3 - Producer UPDATE (Edit):
@app.route('/edit/producer/<int:producer_id>/', methods = ['GET', 'POST'])
def editProducer(producer_id):
    if 'username' not in session:
        flash('You must be logged in to edit a producer.')
        return redirect(url_for('showLogin'))

# check for a valid producer
    producer = check_producer_ID(producer_id)
    if producer == None:
        flash('Producer ID not valid.')
        return redirect(url_for('showAllWines'))

# Make sure the user trying to edit the producer info was the one who entered it.

    user = dbsession.query(User).filter_by(id = producer.added_by_id).one()
    if user.email != session.get('email'):
        flash('Producer information can only be added by the user who added it.')
        return redirect (url_for('showAllWines'))

# For a GET request, send back the editing page.
    if request.method == 'GET':

        editFlag = (user.email == session.get('email'))
        return render_template('edit_producer.html', producer = producer, editFlag = editFlag)

    if request.method == 'POST':
        producer.name = request.form['name'].title()
        producer.region = request.form['region']
        producer.nation = request.form['country']

    # Try to add the edited producer name;
    # If the name was changed to another existing producer name, SQLAlchemy will return an error.
        try:
            dbsession.commit()

        except:
            dbsession.rollback()
            flash('Your changes were not saved - Your edit may have duplicated another entry.')
            return redirect(url_for('viewProducer', producer_id = producer_id))

        flash('Your changes have been saved')
        return redirect(url_for('viewProducer', producer_id = producer_id))


# 4 - Producer DELETE
@app.route('/delete/producer/<int:producer_id>/', methods = ['GET', 'POST'])
def deleteProducer(producer_id):
    if 'username' not in session:
        flash('You must be logged in to delete a producer.')
        return redirect(url_for('showLogin'))

# check for valid producer #


    if request.method == 'GET':
        producer = dbsession.query(Producer).filter_by(id = producer_id).one()
        winelist = dbsession.query(Wine, Variety).join(Variety, Wine.variety_id == Variety.id).filter(Wine.producer_id == producer_id)
        user = dbsession.query(User).filter_by(id = producer.added_by_id).one()
        editFlag = (user.email == session.get('email'))
        return render_template('delete_producer.html', producer = producer, winelist = winelist, editFlag = editFlag)

    if request.method == 'POST':
        if 'username' not in session:
            flash('You must be logged in to delete a wine.')
            return redirect(url_for('showLogin'))

        wines = dbsession.query(Wine).filter(Wine.producer_id == producer_id).all()
        reports = dbsession.query(Report).join(Wine, Wine.id == Report.wine_id).\
                                          join(Producer, Wine.producer_id == Producer.id).\
                                          filter(Wine.producer_id == Producer.id).all()

        producer = dbsession.query(Producer).filter_by(id = producer_id).one()

        for report in reports:
            dbsession.delete(report)
        for wine in wines:
            dbsession.delete(wine)
        dbsession.delete(producer)
        dbsession.commit()
        flash('Producer and related data deleted!')
        return redirect(url_for('showAllWines'))

# Wine CRUD Operations

@app.route('/add/wine/', methods = ['GET', 'POST'])
def addWine():

    if 'username' not in session:
        flash('You must be logged in to add a wine.')
        return redirect(url_for('showLogin'))

    if request.method == 'POST':
        newWineProducer = request.form['producer']
        newWineVariety = request.form['variety'].title()
        newWineVintage = request.form['vintage']
        newWineURL = request.form['imageURL']
        newWineTag = request.form['tags']

        # make sure this submission is not already in the database:
        findWine = dbsession.query(Wine, Variety, Producer).\
            join(Variety, Wine.variety_id == Variety.id).\
            join(Producer, Wine.producer_id == Producer.id).\
            filter(Producer.name.ilike(newWineProducer)).\
            filter(Variety.name.ilike(newWineVariety)).\
            filter(Wine.vintage == newWineVintage)
        findWineCount = findWine.count()

        # if a match is found, send user to the error page.
        if (findWineCount > 0):
            return render_template("duplicate_wine.html", wine = findWine.first())

        # if the producer is not in the db, send the user to the
        # producer_error page.
        newWineProducerId = dbsession.query(Producer.id).\
            filter(func.lower(Producer.name) == func.lower(newWineProducer))
        if not newWineProducerId:
            return render_template("producer_error.html", producer = newWineProducer)

        # the producer checked out, so get the variety ID and add the wine
        newWineVarietyId = dbsession.query(Variety.id).\
            filter(func.lower(Variety.name) == func.lower(newWineVariety))
        if not newWineVarietyId:
            flash('Variety Selection Error. Please select a variety from the list.')
            return render_template("add_wine.html")
        user_id = getUserId(session.get('email'))
        wine = Wine (vintage = newWineVintage,
                     variety_id=newWineVarietyId,
                     producer_id = newWineProducerId,
                     tag = newWineTag,
                     imageURL = newWineURL,
                     added_by_id = user_id)
        dbsession.add(wine)
        dbsession.commit()
        flash('New wine added!')
        return redirect(url_for('viewWine', wine_id=wine.id))

    if request.method == 'GET':
        now = datetime.datetime.now()
        year = now.year
        producers = dbsession.query(Producer.name).order_by(asc(Producer.name))
        varieties = dbsession.query(Variety.name).order_by(asc(Variety.name))
        return render_template ("add_wine.html", varieties = varieties, producers = producers, year = year)

# public wine view by id #
@app.route('/view/wine/<int:wine_id>/')
def viewWine(wine_id):
    try:
        wine = dbsession.query(Wine, Producer, Variety, User).\
            join(Variety, Wine.variety_id == Variety.id).\
            join (Producer, Wine.producer_id == Producer.id).\
            join (User, Wine.added_by_id == User.id).\
            filter(Wine.id == wine_id).one()
    except:
            flash('No entry for wine ID: {} found.'.format(wine_id))
            return redirect(url_for('showAllWines'))

    reports = dbsession.query(Report).filter(Report.wine_id == wine_id).all()
    return render_template("view_wine.html", wine = wine, reports = reports)

@app.route('/edit/wine/<int:wine_id>/', methods = ['GET', 'POST'])
def editWine(wine_id):
    # check for user login status
    if request.method == 'GET':
        if 'username' not in session:
            flash('You must be logged in to edit a wine.')
            return redirect(url_for('showLogin'))
    # if the user is logged in, see if there's a record for the wine ID.
    # if the wine exists, the details will be used later, so make a join-table query
    # so we don't have to send another query to get them.
        try:
            wine = dbsession.query(Wine, Producer, Variety, User).\
                join(Variety, Wine.variety_id == Variety.id).\
                join (Producer, Wine.producer_id == Producer.id).\
                join (User, Wine.added_by_id == User.id).\
                filter(Wine.id == wine_id).one()
    # if there's no record for this wine ID, show error message and display all wines:
        except:
            flash('No entry for wine ID: {} found.'.format(wine_id))
            return redirect(url_for('showAllWines'))

    # check to see if this user added this wine; if not, show error message.
        if wine.User.email == session.get('email'):
            return render_template("edit_wine.html", wine = wine)
        else:
            flash('Only the original poster may edit this wine entry.')
            return redirect(url_for('showAllWines'))

    if request.method == 'POST':
        # check to see if the wine id in the POST is valid:
        try:
            wine = dbsession.query(Wine, Producer, Variety, User).\
                join(Variety, Wine.variety_id == Variety.id).\
                join (Producer, Wine.producer_id == Producer.id).\
                join (User, Wine.added_by_id == User.id).\
                filter(Wine.id == wine_id).one()

        # if there's no record for this wine ID, show error message and display all wines:
        except:
            flash('ERROR: Wine (ID: {}) not found.'.format(wine_id))
            return redirect(url_for('showAllWines'))

        if 'username' not in session:
            flash('You must be logged in to edit a wine.')
            return redirect(url_for('showLogin'))

        if wine.User.email != session.get('email'):
            flash('Only the original poster may edit their wine entry.')
            return redirect(url_for('showAllWines'))

        newWineURL = request.form['imageURL']
        newWineTag = request.form['tag']
        wine.Wine.imageURL = newWineURL
        wine.Wine.tag = newWineTag
        dbsession.commit()
        flash('Your changes have been saved!')
        return redirect(url_for('viewWine', wine_id = wine_id))

@app.route('/delete/wine/<int:wine_id>/', methods = ['GET', 'POST'])
def deleteWine(wine_id):

    # ****TO DO: Check for valid wine ID ***
    if request.method == 'GET':
        if 'username' not in session:
            flash('You must be logged in to delete a wine.')
            return redirect(url_for('showLogin'))

        wine = dbsession.query(Wine, Producer, Variety).\
            join(Variety, Wine.variety_id == Variety.id).\
            join (Producer, Wine.producer_id == Producer.id).\
            filter(Wine.id == wine_id).one()
        return render_template("delete_wine.html", wine = wine)

    if request.method == 'POST':
        if 'username' not in session:
            flash('You must be logged in to delete a wine.')
            return redirect(url_for('showLogin'))
        wine = dbsession.query(Wine).filter(Wine.id == wine_id).one()
        dbsession.delete(wine)
        dbsession.commit()
        flash('Entry deleted!')
        return redirect(url_for('showAllWines'))

@app.route('/add/report/<int:wine_id>/', methods = ['GET', 'POST'])
def addReport(wine_id):
    if request.method == 'GET':
        if 'username' not in session:
            flash('You must be logged in make a wine report.')
            return redirect(url_for('showLogin'))
        wine = dbsession.query(Wine, Producer, Variety).\
            join(Variety, Wine.variety_id == Variety.id).\
            join (Producer, Wine.producer_id == Producer.id).\
            filter(Wine.id == wine_id).one()
        return render_template('add_wine_report.html', wine = wine)

    if request.method == 'POST':

        if 'username' not in session:
            flash('You must be logged in make a wine report.')
            return redirect(url_for('showLogin'))
        user = dbsession.query(User).filter(User.email == session['email']).one()
        now = datetime.datetime.now()
        new_report = Report(wine_id = wine_id, user_report = request.form['report'],\
        user_id = user.id, entry_time = now)
        dbsession.add(new_report)
        dbsession.commit()
        flash('Thank you for adding your report!')
        return redirect(url_for('viewWine', wine_id = wine_id))


@app.route('/JSON/<int:producer_id>')
def wineListJSON(producer_id):
    json_producer = dbsession.query(Producer).filter(Producer.id == producer_id)
    json_dict={}
    wines_to_jsonify = dbsession.query(Wine, Producer, Variety).\
                        join(Variety, Wine.variety_id == Variety.id).\
                        join(Producer, Wine.producer_id == Producer.id).\
                        filter(Producer.id == producer_id).all()
    wines_to_jsonify = dbsession.query(Wine).\
                       filter_by(producer_id = producer_id).all()
    return jsonify(Wine = [i.serialize for i in wines_to_jsonify])


def duplicateWineError(wine_id):
    return render_template ("duplicate.html")

# User Helper Functions

def createUser(session):
    newUser = User(name = session['username'], email = session['email'])
    dbsession.add(newUser)
    dbsession.commit()
    user = dbsession.query(User).filter(User.email==session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = dbsession.query(User).filter_by(id = user_id).one()
    return user

def getUserId(email):
    try:
        user = dbsession.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# Valid Producer Check
def check_producer_ID(producer_id):
    try:
        producer = dbsession.query(Producer).filter_by(id = producer_id).one()
        return producer

    except:
        return None


if __name__ == '__main__':
    # use a new secret key each time the program is run so that session info is cleared.
    #app.secret_key = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(32))
    app.secret_key = "li5900kyg03hdf42dzhf7"
    app.debug = True
    app.run(host='0.0.0.0', port=5000)