import os
import sys
from flask import Flask, render_template, request, url_for, session
import oauth2 as oauth
# import requests
import urlparse
import json
import tweepy
# import unicodedata

# For all those who get a chance to have a look at this code..... folks,
# must listen to the song "Let Her Go" by The Passenger
app = Flask(__name__)

request_token_url = 'https://twitter.com/oauth/request_token'
access_token_url = 'https://twitter.com/oauth/access_token'
authorize_url = 'https://twitter.com/oauth/authorize'
show_user_url = 'https://api.twitter.com/1.1/users/show.json'

CONSUMER_KEY = ''
CONSUMER_SECRET = ''
ACCESS_TOKEN = ""
ACCESS_TOKEN_SECRET = ""
OAUTH_TOKEN = ""
OAUTH_VERIFIER = ""
REAL_OAUTH_TOKEN = ""
REAL_OAUTH_TOKEN_SECRET = ""
oauth_store = {}


@app.route('/')
def hello():
    return render_template('index.html')


@app.route('/start')
def start():
    # Generate the OAuth request tokens, then display them
    # Create your consumer with the proper key/secret.
    consumer = oauth.Consumer(key=CONSUMER_KEY, secret=CONSUMER_SECRET)
    # Create our client.
    client = oauth.Client(consumer)

    # The OAuth Client request works just like httplib2 for the most part.
    resp, content = client.request(request_token_url, "GET")
    # print resp
    # print content
    if resp['status'] != '200':
        error_message = "Invalid response %s" % resp['status']
        return render_template('error.html', error_message=error_message)

    request_token = dict(urlparse.parse_qsl(content))
    oauth_token = request_token['oauth_token']
    oauth_token_secret = request_token['oauth_token_secret']

    # print oauth_token
    # print oauth_token_secret

    global ACCESS_TOKEN
    ACCESS_TOKEN = str(oauth_token)
    global ACCESS_TOKEN_SECRET
    ACCESS_TOKEN_SECRET = str(oauth_token_secret)

    session['ACCESS_TOKEN'] = ACCESS_TOKEN
    session['ACCESS_TOKEN_SECRET'] = ACCESS_TOKEN_SECRET

    # print("ACCESS TOKEN : ", ACCESS_TOKEN)
    # print("ACCESS TOKEN SECRET: ", ACCESS_TOKEN_SECRET)

    oauth_store[oauth_token] = oauth_token_secret
    return render_template('start.html', authorize_url=authorize_url, oauth_token=oauth_token, request_token_url=request_token_url)


@app.route('/callback')
def callback():
    # Accept the callback params, get the token and
    # call the API to display this user's name and handle
    oauth_token = request.args.get('oauth_token')
    oauth_verifier = request.args.get('oauth_verifier')
    oauth_denied = request.args.get('denied')

    global OAUTH_TOKEN
    OAUTH_TOKEN = oauth_token
    session['OAUTH_TOKEN'] = OAUTH_TOKEN
    # print("OAUTH_TOKEN : ", OAUTH_TOKEN)
    global OAUTH_VERIFIER
    OAUTH_VERIFIER = oauth_verifier
    session['OAUTH_VERIFIER'] = OAUTH_VERIFIER

    # print("OAUTH_VERIFIER : ", OAUTH_VERIFIER)
    # if the oauth request was denied, delete
    # our local token and show an error message
    if oauth_denied:
        if oauth_denied in oauth_store:
            del oauth_store[oauth_denied]
        return render_template('error.html', error_message="the OAuth request was denied by this user")
    if not oauth_token or not oauth_verifier:
        return render_template('error.html', error_message="callback param(s) missing")

    # unless oauth_token is still stored locally, return error
    if oauth_token not in oauth_store:
        return render_template('error.html', error_message="oauth_token not found locally")

    oauth_token_secret = oauth_store[oauth_token]

    # if we got this far, we have both call back params
    # and we have found this token locally

    consumer = oauth.Consumer(CONSUMER_KEY, CONSUMER_SECRET)
    token = oauth.Token(oauth_token, oauth_token_secret)

    token.set_verifier(oauth_verifier)
    client = oauth.Client(consumer, token)

    resp, content = client.request(access_token_url, "POST")

    access_token = dict(urlparse.parse_qsl(content))
    session['screen_name'] = access_token['screen_name']
    session['user_id'] = access_token['user_id']

    # These are the tokens you would store long term, someplace safe
    real_oauth_token = access_token['oauth_token']
    real_oauth_token_secret = access_token['oauth_token_secret']

    global REAL_OAUTH_TOKEN
    REAL_OAUTH_TOKEN = real_oauth_token
    session['REAL_OAUTH_TOKEN'] = REAL_OAUTH_TOKEN

    global REAL_OAUTH_TOKEN_SECRET
    REAL_OAUTH_TOKEN_SECRET = real_oauth_token_secret
    session['REAL_OAUTH_TOKEN_SECRET'] = REAL_OAUTH_TOKEN_SECRET
    # print("REAL_OAUTH_TOKEN  :", REAL_OAUTH_TOKEN)
    # print("REAL_OAUTH_TOKEN_SECRET  :", REAL_OAUTH_TOKEN_SECRET)


    # Call api.twitter.com/1.1/users/show.json?user_id={user_id}
    real_token = oauth.Token(real_oauth_token, real_oauth_token_secret)
    real_client = oauth.Client(consumer, real_token)
    real_resp, real_content = real_client.request(show_user_url + '?user_id=' + session['user_id'], "GET")

    if real_resp['status'] != '200':
        error_message = "Invalid response from Twitter API GET users/show : %s" % real_resp['status']
        return render_template('error.html', error_message=error_message)

    response = json.loads(real_content.decode("utf-8"))
    '''
    for key,value in response.items():
        print(key,value)
    '''
    session['friends_count'] = response['friends_count']
    session['statuses_count'] = response['statuses_count']
    session['followers_count'] = response['followers_count']
    session['name'] = response['name']
    session['dp'] = response['profile_image_url']
    # print(dp)
    # don't keep this token and secret in memory any longer
    # del oauth_store[oauth_token]
    session['logged_in'] = True
    session['MESSAGE'] = []
    session['MESSAGE'].append("blank")
    return render_template('callback-success.html',message=session['MESSAGE'],dp=session['dp'],screen_name=session['screen_name'], user_id=session['user_id'], name=session['name'],
        friends_count=session['friends_count'], statuses_count=session['statuses_count'], followers_count=session['followers_count'], access_token_url=access_token_url)


@app.route('/PostTweet', methods=['POST'])
def PostTweet():
    if session.get('logged_in') != True:
        session['ErrorMessage']="Please Login First!"
        return redirect("index.html")
    else:
        tweet = request.form['tweet']

        # print(tweet)
        # print(CONSUMER_KEY)
        # print(CONSUMER_SECRET)
        # print(ACCESS_TOKEN)
        # print(ACCESS_TOKEN_SECRET)

        auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
        auth.set_access_token(REAL_OAUTH_TOKEN, REAL_OAUTH_TOKEN_SECRET)
        api = tweepy.API(auth)
        status = api.update_status(status=tweet)
        session['MESSAGE']=[]
        session['MESSAGE'].append("Yay!...Tweeted Successfully!")
        return render_template('callback-success.html',message=session['MESSAGE'],dp=session['dp'],screen_name=session['screen_name'], user_id=session['user_id'], name=session['name'],
            friends_count=session['friends_count'], statuses_count=session['statuses_count'], followers_count=session['followers_count'], access_token_url=access_token_url)

@app.route('/HashTagSearch',methods=['POST'])
def HashTagSearchTweet():
    if session.get('logged_in') != True:
        session['ErrorMessage']="Please Login First!"
        return redirect("index.html")
    else:
        auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
        auth.set_access_token(REAL_OAUTH_TOKEN, REAL_OAUTH_TOKEN_SECRET)
        api = tweepy.API(auth)

        search_text = request.form['text']
        search_number = 10
        search_result = api.search(search_text, rpp=search_number)
        session['MESSAGE'] = []
        for i in search_result:
            # print(i.text.encode('UTF-8'))
            session['MESSAGE'].append(i.text.encode('UTF-8'))

        return render_template('callback-success.html',message=session['MESSAGE'],dp=session['dp'],screen_name=session['screen_name'], user_id=session['user_id'], name=session['name'],
            friends_count=session['friends_count'], statuses_count=session['statuses_count'], followers_count=session['followers_count'], access_token_url=access_token_url)

@app.route('/MentionSearch',methods=['POST'])
def MentionSearchTweet():
    if session.get('logged_in') != True:
        session['ErrorMessage']="Please Login First!"
        return redirect("index.html")
    else:
        auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
        auth.set_access_token(REAL_OAUTH_TOKEN, REAL_OAUTH_TOKEN_SECRET)
        api = tweepy.API(auth)
        # removing the retweets and creating our query.
        searchQuery = request.form['text']
        retweet_filter = '-filter:retweets'
        q = searchQuery+retweet_filter

        tweetsPerQry = 10
        new_tweets = api.search(q=searchQuery, count=tweetsPerQry)
        session['MESSAGE'] = []
        for i in new_tweets:
            session['MESSAGE'].append(i.text.encode('UTF-8'))

        return render_template('callback-success.html',message=session['MESSAGE'],dp=session['dp'],screen_name=session['screen_name'], user_id=session['user_id'], name=session['name'],
            friends_count=session['friends_count'], statuses_count=session['statuses_count'], followers_count=session['followers_count'], access_token_url=access_token_url)

@app.route('/SearchTextTweet',methods=['POST'])
def SearchTextTweet():
    if session.get('logged_in') != True:
        session['ErrorMessage']="Please Login First!"
        return redirect("index.html")
    else:
        auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
        auth.set_access_token(REAL_OAUTH_TOKEN, REAL_OAUTH_TOKEN_SECRET)
        api = tweepy.API(auth)
        # removing the retweets and creating our query.
        searchQuery = request.form['text']
        retweet_filter = '-filter:retweets'
        q = searchQuery+retweet_filter

        tweetsPerQry = 10
        new_tweets = api.search(q=searchQuery, count=tweetsPerQry)
        session['MESSAGE'] = []
        for i in new_tweets:
            session['MESSAGE'].append(i.text.encode('UTF-8'))

        return render_template('callback-success.html',message=session['MESSAGE'],dp=session['dp'],screen_name=session['screen_name'], user_id=session['user_id'], name=session['name'],
            friends_count=session['friends_count'], statuses_count=session['statuses_count'], followers_count=session['followers_count'], access_token_url=access_token_url)

@app.route('/ViewAllMyTweets',methods=['POST'])
def ViewAllMyTweets():
    if session.get('logged_in') != True:
        session['ErrorMessage']="Please Login First!"
        return redirect("index.html")
    else:
        auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
        auth.set_access_token(REAL_OAUTH_TOKEN, REAL_OAUTH_TOKEN_SECRET)
        api = tweepy.API(auth)

        mylasttentweets = api.user_timeline(screen_name=session['screen_name'], count=10)
        session['MESSAGE'] = []
        for i in mylasttentweets:
            session['MESSAGE'].append(i.text.encode('UTF-8'))

        return render_template('callback-success.html',message=session['MESSAGE'],dp=session['dp'],screen_name=session['screen_name'], user_id=session['user_id'], name=session['name'],
            friends_count=session['friends_count'], statuses_count=session['statuses_count'], followers_count=session['followers_count'], access_token_url=access_token_url)

@app.route('/Logout', methods=['POST'])
def Logout():
    if session.get('logged_in') != True:
        session['ErrorMessage']="Please Login First!"
        return redirect("index.html")
    else:
        session['logged_in']=False
        session.clear()

    session["__invalidate__"] = True
    return render_template('index.html')

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_message='uncaught exception'), 500

@app.after_request
def remove_if_invalid(response):
    if "__invalidate__" in session:
        response.delete_cookie(app.session_cookie_name)
    return response

if __name__ == '__main__':
    app.secret_key = os.urandom(24)
    app.run()
