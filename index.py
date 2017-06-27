#/usr/bin/env python
from flask import Flask, url_for, session, redirect
from flask import request, render_template, flash
from flask import jsonify, make_response, send_from_directory
from oauth2client.client import flow_from_clientsecrets
from flask import session as login_session
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from oauth2client.client import FlowExchangeError
from werkzeug import secure_filename
from db_setup import Base, User, Category, Item, md5Hasher
import json
import httplib2
import requests
import string
import random
import os
import time


app = Flask(__name__)
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Items Category"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalogitem.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

global login_session
# Register


@app.route('/reg', methods=['GET', 'POST'])
def registerUser():
    if request.method == 'POST':
        user = request.form['username']
        pswd = request.form['password']
        if len(user) and len(pswd) >= 6:
            try:
                checkUser = session.query(
                    User).filter_by(username=user).count()
            except:
                return "Error"
            if checkUser == 0:
                try:
                    new = User(username=user, password=md5Hasher(pswd), avatar='https://cdn1.iconfinder.com/data/icons/mix-color-4/502/Untitled-1-512.png')
                    session.add(new)
                    session.commit()
                    flash("User Created Successfuly")
                    return redirect(url_for('LoginUser'))
                except:
                    flash("An error accurd please try again later!")
                    return "ERROR"
            elif checkUser == 1:
                flash("Sorry the username {} is already in use !".format(user))
        elif len(user) and len(pswd) < 8:
            flash("the Username and password must be at least 6 charechters!")
    return render_template('register.html')


# SignIN
@app.route('/login', methods=['GET', 'POST'])
def LoginUser():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    if request.method == 'POST':
        user = request.form['username']
        password = request.form['password']
        pswd = md5Hasher(request.form['password'])
        check = session.query(User).filter_by(username=user).first()
        if not user:
            flash("Please Enter a valid username and password")
        elif user:
            try:
                if check.username == user and check.password == pswd:
                    login_session['logged'] = 'loggedin'
                    login_session['username'] = user
                    login_session['avatar'] = check.avatar
                    login_session['id'] = check.id
                    render_template('home.html', login=login_session)
                    return redirect(url_for('home'))
                else:
                    return redirect(url_for('LoginUser'), STATE=state)
            except:
                flash("Username or password incorrect")
    else:
        return render_template('login.html', STATE=state)
    return render_template('login.html', STATE=state)


@app.route('/')
@app.route('/home', methods=['GET'])
def home():
    categ = session.query(Category).all()
    items = session.query(Item).order_by('item_id desc').limit(8).all()
    itemTitle = 'Latest Items'
    return render_template('home.html',  login=login_session,
                           categ=categ,
                           items=items,
                           itemTitle=itemTitle)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user\
                                    is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        flash("Current user is already connected.")
        return redirect(url_for('logout', login=login_session))
    login_session['access_token'] = credentials.access_token
    login_session['credentials'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': login_session['access_token'], 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json

    login_session['logged'] = 'loggedin'
    login_session['username'] = data['name']
    login_session['avatar'] = data['picture']
    login_session['email'] = data['email']
    # return render_template('home',login=login_session)
    render_template('home.html', login=login_session)
    return 'ok'


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    login_session['logged'] = ''
    login_session['username'] = ''
    login_session['avatar'] = ''
    try:
        access_token = login_session['access_token']
        print 'In gdisconnect access token is %s', access_token
        print 'User name is: '
        print login_session['username']
        if access_token is None:
            print 'Access Token is None'
            response = make_response(json.dumps(
                'Current user not connected.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        print 'result is '
        print result
        if result['status'] == '200':
            del login_session['logged']
            del login_session['access_token']
            del login_session['gplus_id']
            del login_session['username']
            del login_session['email']
            del login_session['avatar']
            response = make_response(json.dumps(
                'Successfully disconnected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return redirect(url_for('LoginUser'))
        else:
            response = make_response(json.dumps(
                'Failed to revoke token for given user.', 400))
            response.headers['Content-Type'] = 'application/json'
            return redirect(url_for('LoginUser'))
    except:
        flash('Come Back Soon :) ')
    return redirect(url_for('LoginUser'))


@app.route('/addItem', methods=['GET', 'POST'])
def addItem():
    categ = session.query(Category).all()
    if request.method == 'POST':
        name = request.form['item_name']
        image = request.form['item_img']
        desc = request.form['item_description']
        category = request.form['options']
        checkitem = session.query(Item).filter_by(item_name=name).count()
        print checkitem
        if checkitem == 0:
            if name:
                try:
                    new = Item(item_name=name, item_description=desc,
                               item_img=image, item_cat=category)
                    session.add(new)
                    session.commit()
                    return redirect(url_for('home'))
                except:
                    flash("Error while adding new item please try again later")
        else:
            flash("Already Exist")
    return render_template('addItem.html', categ=categ, login=login_session)


@app.route('/addCategory', methods=['GET', 'POST'])
def addCategory():
    if request.method == 'POST':
        name = request.form['cat_name']
        check = session.query(Category).filter_by(cat_name=name).count()
        if check == 0:
            try:
                new = Category(cat_name=name)
                session.add(new)
                session.commit()
                return redirect(url_for('home'))
            except:
                flash("Error while adding new Category please try again later")
        else:
            flash("Already Exist")
    return render_template('addCategory.html', login=login_session)


@app.route('/help', methods=['GET'])
def help():
    return render_template('help.html')



@app.route('/show/category/items/<int:cat_id>', methods=['GET', 'POST'])
def showCatItems(cat_id):
    categ = session.query(Category).all()
    currentCat = session.query(Category).filter_by(cat_id=cat_id).one()
    items = session.query(Item).filter_by(
        item_cat=cat_id).order_by('item_id desc').all()

    itemsCount = session.query(Item).filter_by(item_cat=cat_id).count()
    itemTitle = '%s items :  (%s items)' % (currentCat.cat_name, itemsCount)
    return render_template('showCatItems.html', items=items,
                           login=login_session,
                           categ=categ,
                           itemTitle=itemTitle)


@app.route('/show/item/<int:item_id>', methods=['GET', 'POST'])
def showItem(item_id):
    nemo = session.query(Item).filter_by(item_id=item_id).one()
    return render_template('showItem.html', item=nemo, login=login_session)


@app.route('/catalog/<int:item_id>/edit', methods=['GET', 'POST'])
def EditItem(item_id):
    categ = session.query(Category).all()
    item = session.query(Item).filter_by(item_id=item_id).one()
    if request.method == 'POST':
        if request.form['item_name']:
            if request.form['item_name']:
                item.item_name = request.form['item_name']
            if request.form['item_description']:
                item.item_description = request.form['item_description']
            if request.form['item_img']:
                item.item_img = request.form['item_img']
            if request.form['options']:
                item.item_cat = request.form['options']
            session.add(item)
            session.commit()
            flash('Item Successfully Edited')
            return redirect(url_for('home'))
    return render_template('editItem.html', item=item,
                           categ=categ, login=login_session)


@app.route('/catalog/<int:item_id>/delete', methods=['GET', 'POST'])
def DeleteItem(item_id):
    item = session.query(Item).filter_by(item_id=item_id).one()
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('Item Successfully Deleted!')
        return redirect(url_for('home'))

    return render_template('delete.html', login=login_session)

# JSON API


@app.route('/catalog/JSON', methods=['GET'])
def jsonAPI():
    # Return The Last 10 items
    items = session.query(Item).order_by('item_id DESC').limit(10)
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/categories/JSON', methods=['GET'])
def jsoncatAPI():
    # Return The Categories
    cats = session.query(Category).order_by('cat_id DESC')
    return jsonify(Category=[i.serialize for i in cats])


@app.route('/JSON/category/<int:cat_id>', methods=['GET'])
def JSONgetCat(cat_id):
    # Return The Categories
    cats = session.query(Category).filter_by(cat_id=cat_id).all()
    return jsonify(Category=[i.serialize for i in cats])


@app.route('/JSON/item/<int:item_id>', methods=['GET'])
def JSONgetitm(item_id):
    # Return The Categories
    items = session.query(Item).filter_by(item_id=item_id).all()
    return jsonify(Item=[i.serialize for i in items])

# ENd

if __name__ == "__main__":
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8080)
