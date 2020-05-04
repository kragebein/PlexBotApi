#!/usr/bin/python3.6
''' Plexbot restpi '''
from flask import Flask, request
from flask_restful import Resource, Api
from json import dumps
from flask_jsonpify import jsonify
from papi.api import couchpotato as cp
from papi.api import medusa as me
from papi.api import ttdb
from papi.config import conf
import omdb
import logging
import re
import json
import sqlite3
import sys
import hashlib
import os
import binascii
from plexapi.server import PlexServer
from plexapi.exceptions import NotFound

plex = PlexServer(conf.plex_location, conf.plex_token)
omdb.set_default('apikey', conf.omdb_key)
#title = omdb.get(imdbid='tt0944947')
#data = omdb.get(imdbid='tt0944947', fullplot=True, tomatoes=False, season=1, episode=2)
#plexdata = plex.library.section('Series').get(title['title']).season(1).episode(episode=2)
# sys.exit(1)
# print(plexdata.guid)
# for i in plex.library.sections():
#    print(i.type)
# sys.exit(1)

app = Flask(__name__)
api = Api(app, catch_all_404s=True)
cp = cp()
me = me()


def log(message):
    ''' Own logger function '''
    with open('api.log', '+a') as logfile:
        logfile.write('{}\n'.format(message))
        logfile.close()


class other():
    def __init__(self):
        self.run = 0
        self.array = []

    def sql(self, thekey=None, name=None):
        ''' On init, sql sets up and makes sure db is running 
        or set up array. On further run this will add new keys to db'''
        a = sqlite3.connect('/home/krage/PlexApi/papi/db.db')
        b = a.cursor()
        if self.run == 0:
            query = 'CREATE TABLE IF NOT EXISTS users \
            (id integer PRIMARY KEY, key TEXT NOT NULL, name TEXT NOT NULL)'
            b.execute(query)
            a.commit()
            query = 'SELECT * FROM users;'
            data = b.execute(query).fetchall()
            array = {}
            for i in data:
                array[i[1]] = i[2]
            self.array = array
            self.run = 1
            return None
        try:
            query = 'INSERT INTO users (key, name) \
                VALUES("{}", "{}")'.format(thekey, name)
            b.execute(query)
            a.commit()
            return True
        except Exception as R:
            print(R)
            return False

    def auth(self, key):
        ''' Authenticate user from API KEY '''
        try:
            user = self.array[key]
            return True
        except:
            return False

    def hash_password(self, password):
        '''Hash a password for storing'''
        salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                      salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')[:40]

    def verify_password(self, stored_password, provided_password):
        ''' unused '''
        '''Verify a stored password against one provided by user'''
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512',
                                      provided_password.encode('utf-8'),
                                      salt.encode('ascii'),
                                      100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')[:40]
        return pwdhash == stored_password


x = other()


class adduser(Resource):
    def get(self, key, thekey, name):
        if not x.auth(key):
            logging.info('Unauthorized access to API.')
            return {'message': 'Unauthorized'}
        secret = x.hash_password(thekey + name)
        if x.sql(thekey=secret, name=name):
            logging.info('Added user {}'.format(name))
            x.array[thekey] = name
            return {'result': 'success', 'apiKey': '{}'.format(secret), 'name': '{}'.format(name)}
        else:
            return {'message': 'Couldnt not add user.'}


class search(Resource):
    '''query'''

    def get(self, key, query):
        if not x.auth(key):
            return {'message': 'Unauthorized'}
        results = cp.search(query)
        results.update(me.search(query))
        data = {}
        for i in results:
            data[i] = results[i]
        if len(data) == 0:
            return {'result': 'no matches for query'}

        return jsonify(data)

class imdb(Resource):
    def get(self, key, query, season=None, episode=None):
        if not x.auth(key):
            return {'message': 'Unauthorized'}
        log('{} accessed imdb ({})'.format(x.array[key], query))
        odata = omdb.imdbid(query)
        if not odata:
            return {'message': 'not a valid imdb id'}
        item = odata['title']
        if query is None:
            return {'message': 'missing argument'}
        if odata['type'] in ('movie', 'documentary', 'standup'):
            return {'result': odata}
        if odata['type'] == 'series':
            if season is None and episode is None:
                data = omdb.get(imdbid=query, fullplot=True, tomatoes=False)
                try:
                    plexdata = plex.library.section('Series').get(item)
                    ratingkey = plexdata.guid
                    onplex = True
                except:
                    onplex = False
                    ratingkey = None
                    pass
            elif season != None and episode == None:
                data = omdb.get(imdbid=query, fullplot=True,
                                tomatoes=False, season=season)
                if len(data) is 0:
                    return {'message': 'No such season', 'season': '{}'.format(season)}
                try:
                    plexdata = plex.library.section(
                        'Series').get(item).season(int(season))
                    ratingkey = plexdata.parentRatingKey
                    onplex = True
                except:
                    onplex = False
                    ratingkey = None
                    pass
            elif season != None and episode != None:
                data = omdb.get(imdbid=query, fullplot=True,
                                tomatoes=False, season=season, episode=episode)
                if len(data) is 0:
                    return {'message': 'Invalid combination of seasons and episodes ({}x{})'.format(season, episode)}
                try:
                    plexdata = plex.library.section('Series').get(
                        item).season(int(season)).episode(episode=int(episode))
                    ratingkey = plexdata.grandparentRatingKey
                    onplex = True
                except:
                    onplex = False
                    ratingkey = None
                    pass
            return {'result': data, 'plex': onplex, 'ratingKey': ratingkey}


class dorequest(Resource):
    ''' request object'''

    def get(self, key, query):
        if not x.auth(key):
            return {'message': 'Unauthorized'}
        data = omdb.imdbid(query)
        if len(data):
            return {'result': 'not a valid imdb id'}
        if query is None:
            return {'result': 'missing argument'}
        logging.info('Trying to request {}'.format(query))
        if len(data) == 0:
            return False
        _type = data['type']
        if _type == 'series':
            return_data = me.request(query, data)
        elif _type == 'movie' or 'documentary':
            return_data = cp.request(query, data=data)
        return {'result': return_data}


class missing(Resource):
    ''' handle missing objects'''

    def get(self, key, query, season, episode):
        if not x.auth(key):
            return {'message': 'Unauthorized'}
        log('{} accessed plexbotapi'.format(x.array['key']))
        return {'result': self.missing(key, query, season, episode)}

    def missing(self, key, query, season, episode):
        data = omdb.imdbid(query)
        if not data:
            return {'result': 'not a valid imdb id'}
        if query is None:
            return {'result': 'missing argument'}
        ttdbid = ttdb(query)
        result = json.loads(
            me.get('episode', indexerid=ttdbid, season=season, episode=episode))
        title = data['title']
        api_result = result['result']
        if api_result == 'success':
            episode_name = title + ' - ' + result['data']['name']
            episode_status = result['data']['status']
            if re.match('(Downloaded|Archived)', episode_status):
                # This episode already exists, but we'll force download another version.
                setstatus = json.loads(me.get(
                    'episode.setstatus', status='wanted', indexerid=ttdbid, season=season, episode=episode, force=1))
                logging.info(
                    'Set status of {} to "wanted"\n{}'.format(query, setstatus))
                if setstatus['result'] == 'success':
                    return('Retrieved a new version of {}'.format(episode_name))
                elif setstatus['result'] == 'failure':
                    # Need to print the entire message to debug.
                    return('{}'.format(setstatus))
                elif setstatus['result'] == 'error':
                    return(' {}'.format(setstatus))
                print(setstatus)
            if episode_status == 'Wanted':
                # This episode is already in wanted status, but we can force a direct search instead. #TODO: await this function
                search = json.loads(
                    me.get('episode.search', indexerid=ttdbid, season=season, episode=episode))
                logging.info(
                    'Did a search for wanted episode of {}\n{}'.format(ttdbid, search))
                if search['result'] == 'success':
                    return('Did a new try to find {} and found it, episode coming soon.'.format(episode_name))
                elif search['result'] == 'failure':
                    return('couldnt find the episode {}'.format(episode_name))
                elif search['result'] == 'error':
                    return('an error occured: {}'.format(search))
            if re.match('(Skipped|Ignored|Snatched)', episode_status):
                # This episode has been skipped, ignored or has already been snatched. We'll force a new search.
                search = json.loads(
                    me.get('episode.search', indexerid=ttdbid, season=season, episode=episode))
                logging.info(
                    'Forced a new search of skipped episode from {}\n{}'.format(ttdbid, search))
                if search['result'] == 'success':
                    return('Oops, that episode was missing. Got {}x{} for you.'.format(title, result['data']['name']))
                elif search['result'] == 'failure':
                    return('Tried to find the episode {}, but couldnt find any matches.'.format(episode_name))
                elif search['result'] == 'error':
                    return('something wrong happened{}'.format(search))
        elif api_result == 'error':
            # print(me.get('episode', indexerid=ttdbid, season=1, episode=1)) # debug
            return('{} {}x{} is not a valid combination of seasons and episodes'.format(title, season, episode))
        elif api_result == 'failure':
            return('this show doesnt exist yet.')


class refresh(Resource):
    def get(self, key, query):
        if not x.auth(key):
            return {'message': 'Unauthorized'}
        data = omdb.imdbid(query)
        try:
            if data['type'] in ('movie', 'documentary', 'standup'):
                plex.library.section('Films').get(data['title']).refresh()
            elif data['type'] == 'series':
                plex.library.section('Series').get(data['title']).refresh()
            return {'result': 'Refreshing {}'.format(data['title'])}
        except NotFound:
            return {'message': 'Could not update item'}


class gethelp(Resource):
    def get(self, key):
        return {'result': {'route': 'https://plex.lazywack.no/rest/<apikey>/<route>', 'search': 'querytext', 'missing': 'imdbid/season/episode', 'request': 'imdbid', 'imdb': 'imdbid', 'refresh': 'imdbid'}}


class rest():
    def __init__(self):
        x.sql()
        api.add_resource(search, '/rest/<key>/search/<query>')  # Search route
        # request route
        api.add_resource(dorequest, '/rest/<key>/request/<query>')
        api.add_resource(imdb, '/rest/<key>/imdb/<query>', '/rest/<key>/imdb/<query>/<season>',
                         '/rest/<key>/imdb/<query>/<season>/<episode>')  # Get object data
        # Get missing query
        api.add_resource(
            missing, '/rest/<key>/missing/<query>/<season>/<episode>')
        # adduser route
        api.add_resource(adduser, '/rest/<key>/adduser/<thekey>/<name>')
        api.add_resource(refresh, '/rest/<key>/refresh/<query>')
        api.add_resource(gethelp, '/rest/<key>/help')
        app.run(port='5002', host='0.0.0.0', debug=True)
