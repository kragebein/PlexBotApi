#!/usr/bin/python2.7
''' Reads config from file '''
import configparser


class conf():
    c = configparser.ConfigParser()
    c.read('/home/krage/PlexbotPy/config.cfg')
    client = c['DEFAULT']['client']
    medusa = c['MEDUSA']
    medusa_host = medusa['hostname']
    medusa_key = medusa['apikey']
    medusa_qnew = medusa['quality_new']
    medusa_qold = medusa['quality_old']
    cp = c['COUCHPOTATO']
    cp_host = cp['hostname']
    cp_key = cp['apikey']
    cp_qnew = cp['quality_new']
    cp_qold = cp['quality_old']
    ttdb_key = c['TTDB']['key']
    omdb_key = c['OMDB']['key']
    discord_name = c['DISCORD']['username']
    discord_token = c['DISCORD']['token']
    discord_webhook = c['DISCORD']['webhook']
    discord_webtoken = c['DISCORD']['webhook_token']
    bot = c['BOT']
    bot_user = bot['username']
    bot_password = bot['password']
    bot_thread_id = bot['thread_id']
    bot_intercept = bot['inputfile']
    bot_cookie = bot['cookie']
    bot_log = bot['log']
    data = c['STORAGE']
    storage_series = data['series']
    storage_movies = data['movies']
    plex = c['PLEX']
    plex_location = plex['location']
    plex_token = plex['token']
    taut = c['TAUTULLI']
    taut_location = taut['location']
    taut_token = taut['token']
