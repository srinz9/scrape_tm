# https://github.com/mpalazzolo/apple-music-python

from datetime import datetime, timedelta
import jwt
import requests
from requests.exceptions import HTTPError
import time
import re

class AppleMusicFork:
    """
    This class is used to connect to the Apple Music API and make requests for catalog resources
    """

    def __init__(self, secret_key, key_id, team_id, proxies=None,
                 requests_session=True, max_retries=10, requests_timeout=None, session_length=12):
        """
        :param proxies: A dictionary of proxies, if needed
        :param secret_key: Secret Key provided by Apple
        :param key_id: Key ID provided by Apple
        :param team_id: Team ID provided by Apple
        :param requests_session: Use request Sessions class. Speeds up API calls significantly when set to True
        :param max_retries: Maximum amount of times to retry an API call before stopping
        :param requests_timeout: Number of seconds requests should wait before timing out
        :param session_length: Length Apple Music token is valid, in hours
        """
        self.proxies = proxies
        self._secret_key = secret_key
        self._key_id = key_id
        self._team_id = team_id
        self._alg = 'ES256'  # encryption algo that Apple requires
        self.token_str = ""  # encrypted api token
        self.session_length = session_length
        self.token_valid_until = None
        self.generate_token(session_length)
        self.root = 'https://api.music.apple.com/v1/'
        self.max_retries = max_retries
        self.requests_timeout = requests_timeout
        if requests_session:
            self._session = requests.Session()
        else:
            self._session = requests.api  # individual calls, slower

    def token_is_valid(self):
        return datetime.now() <= self.token_valid_until if self.token_valid_until is not None else False

    def generate_token(self, session_length):
        """
        Generate encrypted token to be used by in API requests.
        Set the class token parameter.
        :param session_length: Length Apple Music token is valid, in hours
        """
        token_exp_time = datetime.now() + timedelta(hours=session_length)
        headers = {
            'alg': self._alg,
            'kid': self._key_id
        }
        payload = {
            'iss': self._team_id,  # issuer
            'iat': int(datetime.now().timestamp()),  # issued at
            'exp': int(token_exp_time.timestamp())  # expiration time
        }
        self.token_valid_until = token_exp_time
        token = jwt.encode(payload, self._secret_key, algorithm=self._alg, headers=headers)
        self.token_str = token if type(token) is not bytes else token.decode()

    def _auth_headers(self):
        """
        Get header for API request
        :return: header in dictionary format
        """
        if self.token_str:
            return {'Authorization': 'Bearer {}'.format(self.token_str)}
        else:
            return {}

    def _call(self, method, url, params):
        """
        Make a call to the API
        :param method: 'GET', 'POST', 'DELETE', or 'PUT'
        :param url: URL of API endpoint
        :param params: API paramaters
        :return: JSON data from the API
        """
        if not url.startswith('http'):
            url = self.root + url

        if not self.token_is_valid():
            self.generate_token(self.session_length)

        headers = self._auth_headers()
        headers['Content-Type'] = 'application/json'

        r = self._session.request(method, url,
                                  headers=headers,
                                  proxies=self.proxies,
                                  params=params,
                                  timeout=self.requests_timeout)
        r.raise_for_status()  # Check for error
        return r.json()

    def _get(self, url, **kwargs):
        """
        GET request from the API
        :param url: URL for API endpoint
        :return: JSON data from the API
        """
        retries = self.max_retries
        delay = 1
        while retries > 0:
            try:
                return self._call('GET', url, kwargs)
            except HTTPError as e:  # Retry for some known issues
                retries -= 1
                status = e.response.status_code
                if status == 429 or (500 <= status < 600):
                    if retries < 0:
                        raise
                    else:
                        print('retrying ...' + str(delay) + ' secs')
                        time.sleep(delay + 1)
                        delay += 1
                else:
                    raise
            except Exception as e:
                print('exception', str(e))
                retries -= 1
                if retries >= 0:
                    print('retrying ...' + str(delay) + 'secs')
                    time.sleep(delay + 1)
                    delay += 1
                else:
                    raise

    def _post(self, url, **kwargs):
        return self._call('POST', url, kwargs)

    def _put(self, url, **kwargs):
        return self._call('PUT', url, kwargs)

    # def addSong(self, playlistID, songID):
    #     url = self.root + 'me/library/playlists/{}/tracks'.format(playlistID)
    #     data = {
    #         "id": songID,
    #         "type": "songs"
    #     }
    #     return self._session.post(url, id=songID, type='songs')

    # Search
    def search(self, term, storefront='us', l=None, limit=None, offset=None, types=None, hints=False, os='linux'):
        """
        Query the Apple Music API based on a search term
        :param term: Search term
        :param storefront: Apple Music store front
        :param l: The localization to use, specified by a language tag. Check API documentation.
        :param limit: The maximum amount of items to return
        :param offset: The index of the first item returned
        :param types: A list of resource types to return (e.g. songs, artists, etc.)
        :param hints: Include search hints
        :param os: Operating System being used. If search isn't working on Windows, try os='windows'.
        :return: The search results in JSON format
        """
        url = self.root + 'catalog/{}/search'.format(storefront)
        if hints:
            url += '/hints'
        term = re.sub(' +', '+', term)
        if types:
            type_str = ','.join(types)
        else:
            type_str = None

        if os == 'linux':
            return self._get(url, term=term, l=l, limit=limit, offset=offset, types=type_str)
        elif os == 'windows':
            params = {
                'term': term,
                'limit': limit,
                'offset': offset,
                'types': type_str
            }

            # The params parameter in requests converts '+' to '%2b'
            # On some Windows computers, this breaks the API request, so generate full URL instead
            param_string = '?'
            for param, value in params.items():
                if value is None:
                    continue
                param_string = param_string + str(param) + '=' + str(value) + '&'
            param_string = param_string[:len(param_string) - 1]  # This removes the last trailing '&'

            return self._get(url + param_string)
        else:
            return None


secret_key = ""
key_id = ''
team_id = ''

am = AppleMusicFork(secret_key, key_id, team_id)
results = am.search('KRYPTONITE', types=['songs'], limit=2)

results['results']

# response = am.addSong('p.V7VY8bbs6gGRdz', '1440664900')# ().post(url, data=data)
# response