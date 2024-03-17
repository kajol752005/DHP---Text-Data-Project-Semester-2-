from flask import Flask, render_template, request, redirect, url_for, session   # Import Flask and related modules
from google_auth_oauthlib.flow import Flow                                      # Import Google OAuth flow module
import os                                                                       # Import os module for operating system functionalities
import google.auth.transport.requests                                           # Import Google authentication transport requests module
from google.oauth2 import id_token                                              # Import Google OAuth2 ID token module
import requests                                                                 # Import requests module for making HTTP requests
from bs4 import BeautifulSoup                                                   # Import BeautifulSoup for web scraping
import nltk                                                                     # Import NLTK for natural language processing tasks
nltk.download('universal_tagset')
from nltk.tokenize import sent_tokenize, word_tokenize                          # Import NLTK tokenizers
from nltk import pos_tag                                                        # Import NLTK part-of-speech tagging
import psycopg2                                                                 # Import psycopg2 for PostgreSQL database interaction


from requests_oauthlib import OAuth2Session
# Set environment variable to allow insecure transport for OAuth2Session
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Initialize Flask app
app = Flask(__name__)

# Generate a secret key for the Flask session
app.secret_key = "12345"
# Define Google OAuth client ID
client_id = '485950043701-cri7tkmprkdmbq49cvd67m91ds05lhhd.apps.googleusercontent.com'
# Define Google OAuth client secret
client_secret = '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'  
# Download NLTK data
nltk.download('punkt')
nltk.download('averaged_perceptron_tagger')

# Path to Google OAuth client secrets file
client_secrets_file ='client_secret_485950043701-cri7tkmprkdmbq49cvd67m91ds05lhhd.apps.googleusercontent.com.json'

# OAuth scopes required for authentication
scopes = ['https://www.googleapis.com/auth/userinfo.profile',
          'https://www.googleapis.com/auth/userinfo.email',
          'openid']

# Redirect URI for the OAuth flow
redirect_uri = 'https://url-extractor-apoi.onrender.com/protected'

# Create the OAuth flow object
flow = Flow.from_client_secrets_file(client_secrets_file, scopes=scopes, redirect_uri=redirect_uri)

# Connect to the PostgreSQL database
conn = psycopg2.connect(
    dbname='dhp2024_dqb4',
    user='dhp2024_dqb4_user',
    password='NDmWyNySiUG2JvvWdaXfPErQYPoM0Ghm',
    host='dpg-cnmld6ev3ddc73fkespg-a')

# Create a database cursor
cur = conn.cursor()

# Create the news_analysis table if it doesn't exist
cur.execute('''CREATE TABLE IF NOT EXISTS news_analysis (
            url TEXT,
            news_heading TEXT,
            news_text TEXT,
            num_sentences INTEGER,
            num_words INTEGER,
            pos_tags TEXT,
            publication_datetime TEXT,
            article_titles TEXT,
            article_links TEXT,
            user_google_id TEXT
        )
        ''')
conn.commit()

# Function to extract publication datetime from the particular class of a given URL
def extract_publication_datetime(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        pub = soup.find('div', class_='xf8Pm byline')
        if pub:
            publication_datetime = pub.get_text()
            return publication_datetime
        else:
            return "Not Found"

    except Exception as e:
        return str(e)

# Function to extract news heading from a given URL
def extract_news_heading(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        heading_element = soup.title
        if heading_element:
            news_heading = heading_element.get_text()
            return news_heading.strip()
        else:
            return "Heading not found"

    except Exception as e:
        return str(e)

# Function to extract news text from the particular class of a given URL
# Used encoding decoding to handle errors during text conversion.
def extract_news_text(url):
    try:
        response = requests.get(url)
        response.encoding = 'utf-8'  # Set the encoding explicitly to UTF-8
        soup = BeautifulSoup(response.text, 'html.parser')

        elements_hnmdr = soup.find_all(class_='HNMDR')
        elements_s30j = soup.find_all(class_='_s30J clearfix')

        text_hnmdr = ' '.join([element.get_text() for element in elements_hnmdr])
        text_s30j = ' '.join([element.get_text() for element in elements_s30j])

        news_text = text_hnmdr + ' ' + text_s30j
        return news_text

    except Exception as e:
        return str(e)

# Function to analyze text using NLTK
# Stored as a dictionary to display it in nicely formatted table
def analyze_text(news_text):
    words = word_tokenize(news_text)
    pos_tags = nltk.pos_tag(words, tagset='universal')

    pos_dict = {}  # Dictionary to store POS tags and their corresponding words

    for word, pos_tag in pos_tags:
        if pos_tag not in pos_dict:
            pos_dict[pos_tag] = [word]
        else:
            pos_dict[pos_tag].append(word)

    return pos_dict

# Function to extract articles table from the particular class of a given URL
def extract_articles_table(url):
    articles_dict = {}

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        title_elements = soup.find_all(class_='yCs_c')
        link_elements = soup.find_all(class_='Hn2z7 undefined')

        for title, link in zip(title_elements, link_elements):
            title_text = title.get_text().strip()
            link_url = link['href']
            articles_dict[title_text] = link_url

    except Exception as e:
        print("Error:", e)

    return articles_dict

# Function to store analysis results in the database
def store_analysis(url, news_heading, news_text, num_sentences, num_words, pos_tags, publication_datetime, article_titles, article_links, user_google_id):
    cursor = conn.cursor()
    cursor.execute("INSERT INTO news_analysis (url, news_heading, news_text, num_sentences, num_words, pos_tags, publication_datetime, article_titles, article_links, user_google_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (url, news_heading, news_text, num_sentences, num_words, str(pos_tags), publication_datetime, article_titles, article_links, user_google_id))
    conn.commit()

# Route for analyzing news
@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form['url']
    news_heading = extract_news_heading(url)
    news_text = extract_news_text(url)
    pos_tags = analyze_text(news_text)
    num_sentences = len(sent_tokenize(news_text))
    num_words = len(word_tokenize(news_text))
    publication_datetime = extract_publication_datetime(url)
    articles = extract_articles_table(url)
    article_titles = list(articles.keys())
    article_links = list(articles.values())
    user_google_id = request.form['user']
    store_analysis(url, news_heading, news_text, num_sentences, num_words, pos_tags, publication_datetime, article_titles, article_links, user_google_id)
    return render_template('results.html', url=url, news_heading=news_heading, news_text=news_text, num_sentences=num_sentences, num_words=num_words, pos_tags=pos_tags, publication_datetime=publication_datetime, articles=articles, article_titles=article_titles, article_links=article_links, user_google_id=user_google_id)

# Define route for the home page
@app.route('/')
def portal():
    return render_template('index.html')

# Define route for the index page
@app.route('/index')
def index():
    # Check if the user is logged in
    if 'username' in session:
        # Redirect to the protected page if logged in
        return redirect(url_for('protected'))
    else:
        # Redirect to the login page if not logged in
        return redirect(url_for('login'))

# Define route for the login page
@app.route('/login')
def login():
    # Initialize Google OAuth2Session with required parameters
    google = OAuth2Session(client_id, redirect_uri=redirect_uri, scope='https://www.googleapis.com/auth/userinfo.email')
    # Generate authorization URL and state for Google OAuth2 authentication
    authorization_url, state = google.authorization_url('https://accounts.google.com/o/oauth2/auth', access_type='offline', prompt='consent')
    # Store OAuth state in session
    session['oauth_state'] = state
    # Redirect user to Google authorization URL for login
    return redirect(authorization_url)

# Define route for the callback URL after successful Google OAuth2 authentication
@app.route('/callback')
def callback():
    # Initialize Google OAuth2Session with client ID and OAuth state from session
    google = OAuth2Session(client_id, state=session['oauth_state'], redirect_uri=redirect_uri)
    # Fetch OAuth2 token using authorization response URL
    token = google.fetch_token('https://accounts.google.com/o/oauth2/token', client_secret=client_secret, authorization_response=request.url)
    # Store Google token in session
    session['google_token'] = token
    # Retrieve user information from Google
    userinfo = google.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
    # Store user email in session
    session['username'] = userinfo['email']
    # Redirect to the index page after successful authentication
    return redirect(url_for('index'))

# Define route for the protected page
@app.route('/protected')
def protected():
    # Check if the user is logged in and the email matches a specific email
    if 'username' in session and session['username'] == 'kajolkashipuri2005@gmail.com':
        # Fetch all records from the news_analysis table
        cur.execute("SELECT * FROM news_analysis")
        url_history = cur.fetchall()
        # Render the admin panel template with URL history data
        return render_template("admin_panel.html", url_history=url_history)
    else:
        # Redirect to the login page if not logged in or email does not match
        return redirect(url_for('login'))

# Start the Flask application if this script is executed
if __name__ == '__main__':
    app.run(debug=True)
