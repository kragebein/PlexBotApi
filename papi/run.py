#!/usr/bin/python3.6
''' Plexbot restpi '''
import omdb
import logging
import re
import json
import sqlite3
import sys
import hashlib
import os
import binascii
import datetime
import discord
import time
from flask import Flask, request
from flask_restful import Resource, Api
from json import dumps
from flask_jsonpify import jsonify
from papi.api import tapi
from papi.api import couchpotato as cp
from papi.api import medusa as me
from papi.api import ttdb
from papi.api import Tautulli
from papi.config import conf
from plexapi.server import PlexServer
from plexapi.exceptions import NotFound
from discord import Webhook, RequestsWebhookAdapter

plex = PlexServer(conf.plex_location, conf.plex_token)
omdb.set_default('apikey', conf.omdb_key)

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
        self.announces = []
        with open('papi/announces.json', 'r') as g:
            self.announces = json.loads(g.read())
            g.close()

        

    def sql(self, thekey=None, name=None):
        ''' On init, sql sets up and makes sure db is running 
        or register keys in array from db if it already exists. On further run this will add new keys to db'''
        
        a = sqlite3.connect(conf.selfpath + '/papi/db.db')
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

class status(Resource):
    ''' Retrieve status of the plex server '''
    def get(self, key):
        if not x.auth(key):
            return {'message': 'Unauthorized'}
        taut = Tautulli()
        try:
            activity = taut.get('get_activity')
            last_add = taut.get('get_recently_added', count=1)
            since = int(time.time()) - int(last_add['response']['data']['recently_added'][0]['added_at'])
            since = int(since) / 60 / 60
            last_meta = taut.get('get_metadata', rating_key=last_add['response']['data']['recently_added'][0]['rating_key'])
            last_title = last_meta['response']['data']['full_title']
            stream_count_total = activity['response']['data']['stream_count']
            bandwidth = round(activity['response']['data']['total_bandwidth'] * 0.0009765625 / 8,1) #bandwidth in mb/s
            client_bandwidth = []
            for i in activity['response']['data']['sessions']:
                client_bandwidth.append(round(float(i['bandwidth']) * 0.0009765625 / 8,1))

            return {'result': activity, 'last': last_meta, 'last_since': str(since)[0:4], 'stream_count': stream_count_total, 'total_bandwidth': bandwidth, 'bandwidth': client_bandwidth}
        except Exception as R:
            
            return {'message': 'error, couldnt retrieve status. {}'.format(R)}

class search(Resource):
    '''query'''
       
    def get(self, key, query):
        if not x.auth(key):
            return {'message': 'Unauthorized'}
        # Check if search string is imdb url or imdbid
        if 'http' in query:
            query.split('/')[3]
        _regex = '^.t.{0,9}'
        if re.match(_regex, query):
            # imdbid found, lets return from here instead.
            y = imdb()
            data = y.get(key, query)
            
            results = {}
            results[query] = {'title': data['result']['title'], 
                            'year': data['result']['year'],
                            'type': data['result']['type'],
                            'plex': data['plex']}
            print(results)
            return jsonify(results)
        else:
            # The search string was not a imdbid, do a regular search instead
            pass
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
            # We need to add here if the item is on plex or not.
            try:
                plexdata = plex.library.section('Films').get(item)
                ratingkey = plexdata.guid
                onplex = True
            except:
                onplex = False
                ratingkey = None
                pass
            return {'result': odata, 'plex': onplex, 'ratingKey': ratingkey}

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
        if len(data) == 0:
            return {'result': 'not a valid imdb id: {}'.format(data)}
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
        # WE NEED TO IMPLEMENT A CORRECT RETURN FOR THIS FUNCTION BELOW.
            if return_data == 'exists':
                return {'message': 'already exists on system'}
            elif return_data == 'already_queued':
                return {'message': 'movie is already queued on the system'}
            elif return_data == 'requested':
                return {'result': 'movie was added'}
            elif return_data == 'backend_api_error':
                return {'message': 'backend api error'}
            else:
                return {'message': return_data}
        

class Track(Resource):
    # This absolutely sucks.

    # What data should we get to identify the proper ticket number?
    data = {'location': 'cache', 'name': 'blurb', 'timestamp': '04/08/2020 13:37', 'other': {}, 'other1': {} }

    def __init__(self):
        #Init database
        self.db  = sqlite3.connect('papi/db.db')
        self.sql = self.db.cursor()

    def tracker(self, data):
        # Internal tracker
        query = 'SELECT * from tracker WHERE name REGEX {}'.format(data['name'])
        results = self.sql.execute(query).fetchall()
        if len(results) == 0:
            # No matches to this query. Create new ticket?
            if data['location'] != 'app':
                # make sure the data is coming from the app
                pass
            return
        for i in results:
            if re.match(i['name'], data['name'], re.IGNORECASE):
                # update ticket with new location and timestamp
                
                #i['current'] == data['location']
                #i['latestupdate'] == data['timestamp'] 
                #self.sql.execute('INSERT into tracker (data) ({})'.format(json.dumps(i)))
                # stop exec
                break


    def post(self, key, data):
        # API handler for the tracker
        if not x.auth(key):
            return {'message': 'Unauthorized'}
        # check if resource is tracked, or if we have to create a new tracking.
        pass
    







class missing(Resource):
    ''' handle missing objects'''

    def get(self, key, query, season, episode):
        if not x.auth(key):
            return {'message': 'Unauthorized'}
        #log('{} accessed plexbotapi'.format(x.array['key']))
        return {'result': self.missing(key, query, season, episode)}

    def missing(self, key, query, season, episode):
        data = omdb.imdbid(query)
        if not data:
            return {'result': 'not a valid imdb id'}
        if query is None:
            return {'result': 'missing argument'}
        # check if this show exists with another indexer first and use that ID.
        ttdbid = ttdb(query)
        result = json.loads(me.get('episode', indexerid=ttdbid, season=season, episode=episode))
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

class announce(Resource):

    ''' Announces stuff to discord and makes announce.json available as a list with dicts through the api '''
    def __init__(self):
        self.x = sqlite3.connect('papi/db.db')
        self.sql = self.x.cursor()
        
    def get(self, key, ratingkey):
        if not x.auth(key):
            return {'message': 'Unauthorized'}
        #log('{} accessed plexbotapi'.format(x.array['key']))
        tvdb = tapi.TVDB(conf.ttdb_key, banners=True)
        omdb.set_default('apikey', conf.omdb_key)
        year = datetime.datetime.today().year
        '''function returns viable data from tautulli'''
        taut = Tautulli() # 
        if not isinstance(ratingkey, int):
            ratingkey = int(ratingkey)
        metadata = taut.get('get_metadata', rating_key=ratingkey)
        try:
            text = ''
            _type = metadata['response']['data']['library_name']

        except:
            logging.info('Tried to announce season (ratingkey: {})'.format(ratingkey))
            text = 'Added a new show (rating key: {}), but Tautulli is unable to determine type of show'.format(ratingkey)
            webhook = Webhook.partial(conf.discord_webhook, conf.discord_webtoken, adapter=RequestsWebhookAdapter())
            webhook.send(text, username='Plexbot')
            return(metadata)
        if _type == 'Series':
    
                thetvdb = metadata['response']['data']['parent_guid'].split('//')[1].split('/')[0]
                episode = int(metadata['response']['data']['media_index'])
                season = int(metadata['response']['data']['parent_media_index'])
                _metadata = tvdb.get_series(thetvdb, 'en')
                title = _metadata.SeriesName
                plot = _metadata[season][episode].Overview
                rating = str(_metadata[season][episode].Rating) + '/10'
                episode_name = _metadata[season][episode].EpisodeName
                release = _metadata[season][episode].FirstAired
                
                imdbid = ttdb(thetvdb)
                omdbdata = omdb.imdbid('{}'.format(imdbid))
                url = 'https://www.imdb.com/title/{}/'.format(imdbid)
                if rating == '0/10':
                    rating = 'N/A'
                if release is '':
                    release = str(year) + '*'
                if rating is '' or rating == '/10' or rating == 'N/A':
                    rating = '1.0/10*'
                if plot == '':
                    plot = 'N/A'
                if title == '' or title == 'N/A':
                    title = 'N/A'
                embed = discord.Embed(title='{} ({}x{}) is on Plex!'.format(title, season, episode), url=url, colour=discord.Colour(0xf9c38b))
                embed.add_field(name='Episode name', value=episode_name, inline=False)
                embed.add_field(name='Season', value=season, inline=True)
                embed.add_field(name='Episode', value=episode, inline=True)
                embed.add_field(name='Release date', value=release, inline=True)
                embed.add_field(name='Rating', value=rating, inline=True)
                embed.add_field(name='Plot', value=plot, inline=False)
                try:
                    if omdbdata['poster'] != 'N/A':
                        embed.set_thumbnail(url=omdbdata['poster'])
                except:
                    pass
                embed.set_footer(text='Plexbot.py', icon_url='https://zhf1943ap1t4f26r11i05c7l-wpengine.netdna-ssl.com/wp-content/uploads/2018/01/pmp-icon-1.png')
                announcedata = {'key': ratingkey, 'title': title + ' - ' + episode_name, 'type': _type, 'season': season, 'episode': episode, 'release': str(release), 'rating': rating, 'plot': plot }

        elif _type == 'Films' or _type == '4K Movies' or _type == 'Norsk':
                imdbid = metadata['response']['data']['guid'].split('//')[1].split('?')[0]
                metadata = json.loads(omdb.request(i=imdbid).text)
                title = metadata['Title']
                release = metadata['Released']
                plot = metadata['Plot']
                rating = metadata['Ratings'][0]['Value']
                omdbdata = omdb.imdbid('{}'.format(imdbid))

                if rating == '0/10':
                    rating = 'N/A'
                if release is '':
                    release = str(year) + '*'
                if rating is '' or rating == '/10':
                    rating = '1.0/10*'
                if plot == '':
                    plot = 'N/A'
                if title == '' or title == 'N/A':
                    title = 'N/A'
                url = 'https://www.imdb.com/title/{}/'.format(imdbid)
                embed = discord.Embed(title='New movie "{}" available'.format(title), url=url, colour=discord.Colour(0xf9c38b))
                embed.add_field(name='Original title', value=title)
                embed.add_field(name='Release date', value=release, inline=True)
                embed.add_field(name='Rating', value=rating, inline=True)
                embed.add_field(name='Plot', value=plot)
                try:
                    if omdbdata['poster'] != 'N/A':
                        embed.set_thumbnail(url=metadata['Poster'])
                except:
                    pass
                embed.set_footer(text='Plexbot.py', icon_url='https://zhf1943ap1t4f26r11i05c7l-wpengine.netdna-ssl.com/wp-content/uploads/2018/01/pmp-icon-1.png')
                announcedata = {'key': ratingkey, 'title': title, 'type': _type, 'season': None, 'episode': None, 'release': release, 'rating': rating, 'plot': plot }

        else:
            logging.info('Added rating key {} in new library: {}'.format(ratingkey, _type))
            embed = discord.Embed(title='A new item was added')
            embed.add_field(name='Rating key', value=ratingkey)
            embed.add_field(name='Section', value=_type)
            embed.set_footer(text='Plexbot.py', icon_url='https://zhf1943ap1t4f26r11i05c7l-wpengine.netdna-ssl.com/wp-content/uploads/2018/01/pmp-icon-1.png')
            announcedata = {'key': ratingkey, 'type': _type, 'season': None, 'episode': None, 'release': None, 'rating': None, 'plot': None }
        webhook = Webhook.partial(conf.discord_webhook, conf.discord_webtoken, adapter=RequestsWebhookAdapter())
        webhook.send(text, embed=embed, username='Plexbot')
        
        # Make sure 'other' is updated.
        x.announces.append(announcedata)
        print(x.announces)
        with open('papi/announces.json', 'w') as g:
            g.write(json.dumps(x.announces))
            g.close()
        
        return {'result': 'Announced'}

class getannounce(Resource):
    def get(self, key):
        if not x.auth(key):
            return {'message': 'Unauthorized'}
        
        return x.announces

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
        # Get status of plex server.
        api.add_resource(status, '/rest/<key>/status')
        # adduser route
        api.add_resource(adduser, '/rest/<key>/adduser/<thekey>/<name>')
        api.add_resource(refresh, '/rest/<key>/refresh/<query>')
        api.add_resource(gethelp, '/rest/<key>/help')
        # announce route
        api.add_resource(announce, '/rest/<key>/announce/<ratingkey>') # put 
        api.add_resource(getannounce, '/rest/<key>/getannounce') # get
        app.run(port='5002', host='0.0.0.0', debug=False)
        

