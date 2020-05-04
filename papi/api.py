#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
import json, time, omdb, re, requests, logging, sys
import tvdbsimple as tvdb
#from plexapi.server import PlexServer
from papi.config import conf
conf = conf()
omdb.set_default('apikey', conf.omdb_key)
    
def storage(data, location):
    ''' storage is used for setting up staging area by adding the movie/show to 
    a specific folder starting with the first letter of the title. Will skip "The" if it exists
    for instance /downloads/Series/S for Stargate, or /downloads/Movies/S for The Shining'''
    regex = '^(THE )'
    title = data['title'].upper()
    title = re.sub(regex, '', title)[0:1]
    return(location + title)
   

def ttdb(input): 
    ''' Returns imdbid <=> thetvdbid.
    if you input imdbid, it returns thetvdbid and vice versa '''
    _regex = '^.t.{0,9}'
    tvdb.KEYS.API_KEY = conf.ttdb_key
    search = tvdb.Search()
    if re.search(_regex, input, re.IGNORECASE):
       search = tvdb.Search()
       try:
          response = search.series(imdbId=input)
       except:
          return False
       finally:
           try:
                rating_key = response[0]['id']
                return rating_key
           except:
                return False
    else:
       search = tvdb.Series(input)
       try:
          response = search.info()
       except:
          return False
       imdbid = response['imdbId']
       return imdbid



class couchpotato():
    def get(self, where, **argv):
        url = conf.cp_host + '/api/' + conf.cp_key + '/' + where
        http = requests.get(url, params=argv)
        r = http.text
        return r
    def request(self, imdbid, **argv):
        '''creates a request to couchpotato '''
        status = self.getmovie(imdbid)
        data = argv['data']
        title = data['title']
        try:
            if status['status'] == 'done':
                return '{} ({}) fins allerede på Plex.'.format(title, imdbid)
            elif status['status'] == 'active':
                return 'Filmen \"{}\" ligg allerede i kø.'.format(title)
        except:
            pass
        if not status:
            logging.info('requesting movie {}'.format(imdbid))
            #location = storage(data, conf.storage_movies)
            if int(data['year']) >= 2006:
                initial = conf.cp_qnew
            elif int(data['year']) < 2006:
                initial = conf.cp_qold
            request = json.loads(couchpotato().get('movie.add', force_readd=False, title=data['title'], identifier=imdbid, profile_id=initial))
            try:
                if request['success']:
                    return('La tell filmen "{}". Kommer fortløpanes'.format(title))
            except Exception as r:
                print(request)
                print(r)
                return('{} vart ikke lagt tell :( Sendt debug til logg.'.format(title))
         
    def getmovie(self, imdbid):
        ''' returns data from imdb '''
        if omdb.imdbid(imdbid) is False:
            print('{"error: "This movie doesnt exist on imdb"}')
            return False
        data = json.loads(couchpotato().get('media.get', id=imdbid))
        if data['success'] == False:
            return False
        return data['media']
        
    def search(self, input):
        results = {}
        cp = couchpotato()
        for i in omdb.search_movie(input):
            cp_data = json.loads(cp.get('media.get', id=i['imdb_id']))
            if cp_data['success'] is True:
                status = cp_data['media']['status']
                if status == 'done':
                    result = 'True'
                elif status == 'active':
                    result = 'wishlist'
            elif cp_data['success'] is False:
                result = 'False'
            results[i['imdb_id']] = {'title': i['title'],'year': i['year'],'type': i['type'],'plex': result}
        return results

class medusa():
    def get(self, where, **argv):
            url = conf.medusa_host + '/api/' + conf.medusa_key + '/?cmd=' + where
            http = requests.get(url, params=argv)
            r = http.text
            return r
             
    def getshow(self, input):
        tvdbid = ttdb(input)
        if tvdbid is False:
            return '{"error": "This show doesnt exist on system"}'
        show_data = medusa().get('show', indexerid=tvdbid)
        return show_data

    def request(self, *args):
        if len(args) == 0:
            raise Exception('Request input empty')
        imdbid = args[0]
        imdb_data = args[1]
        title = imdb_data['title']
        tvdbid = ttdb(imdbid)
        if not tvdbid:
            return "Sorry, men {} eksister ikke på thetvdb, og kan ikke requestes.".format(title)
        data = medusa().get('show.cache', tvdbid=tvdbid)
        response = json.loads(data)
        if response['result'] == 'success':
            return 'Sorry, {} fins allerede på systemet.'.format(title)
        # Time to add the show, lets first set the initial request data. 
        indexerid = tvdbid
        status = 'wanted'
        future_status = 'wanted'
        season_folder = 1
        anime = 0
        lang = 'en'
        quality = int(imdb_data['year'][0:4])
        # Set quality status, if its older than 2006, look for low def, if newer, look for high def. 
        if quality > 2006:
            initial = conf.medusa_qnew
        elif quality < 2006:
            initial = conf.medusa_qold
        location = storage(imdb_data, conf.storage_series)
        request = medusa().get('show.addnew', indexerid=indexerid, \
        status=status, future_status=future_status, \
        season_folder=season_folder, initial=initial, \
        location=location, anime=anime, lang=lang)

        try:
            if request['data']['result'] == 'success':
                return('La tell "{}" på Plex. Kommer fortløpanes.'.format(request['data']['name']))
        except:
            logging.debug('Request to medusa failed.. Trying again in 10 seconds..')
            time.sleep(10)
            try:
                if request['data']['result'] == 'success':
                    return('La tell "{}" på Plex. Kommer fortløpanes.'.format(request['data']['name']))
                logging.info('Request Successful!')
                pass
            except:
                logging.debug('Second attempt failed.')
                return('Couldnt add this show, bogus response from medusa:\n{}'.format(request))
        return('error: {}'.format(request))

        
    def search(self, input):
        results = {}
        for i in omdb.search_series(input):
            tvdbid = ttdb(i['imdb_id'])
            medusa_data = json.loads(medusa().get('show.cache', tvdbid=tvdbid))
            status = medusa_data['result']
            if status == 'failure':
                result = 'False'
            if status == 'success':
                result = 'True'
            if status == 'error':
                result = 'error'
            results[i['imdb_id']] = {'title': i['title'],'year': i['year'],'type': i['type'],'plex': result}
        return results

class Tautulli():
    def get(self, where, **argv):
        url = conf.taut_location + '/api/v2?apikey=' + conf.taut_token + '&cmd='+ where
        http = requests.get(url, params=argv)
        r = json.loads(http.text)
        return r
        

