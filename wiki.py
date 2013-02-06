import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#db storage

class Page(db.Model):
    location = db.TextProperty(required = True)

 class Entry(db.Model):
    page = db.ReferenceProperty(Page, collection_name='versions')
    content = db.TextProperty(required = True)
    # author = db.ReferenceProperty(User, required = True)
    timestamp = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def submit(cls, location, content):

        return Entry(page = location, content = content)


# User

def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(username, password, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username + password + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_password(username, password, pw_hash):
    salt = pw_hash.split(',')[0]
    return pw_hash == make_pw_hash(username, password, salt)

def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    username = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, id):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, username):
        user = User.all().filter('username =', username).get()
        return user

#    @classmethod
    def register(cls, username, password, email=None):
        pw_hash = make_pw_hash(username, password)
        return User(parent = users_key(),
                    username = username,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def get_user(cls, username, password):
        user = cls.by_name(username)
        if user and valid_password(username, password, user.pw_hash):
            return user

#class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        user = User.by_name(self.username)
        if user:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            user = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/signup')

## Wiki

class Page(db.Model):
    location = db.TextProperty(required = True)
    
    
class Entry(db.Model):
    page = db.ReferenceProperty(Page, collection_name='versions')
    content = db.TextProperty(required = True)
    timestamp = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def submit(cls, location, content):
        return Entry(page = location, content = content)

    @classmethod
    def get_history(cls, location):
        pass

# User stuff

secret = 'magic'

def make_secure_value(value):
    return '%s|%s' % (value, hmac.new(secret, value).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BaseHandler(webapp2.RequestHandler):
    #used for shorthand "self.write"
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    #prints templates
    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

    #renders templates
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def set_secure_cookie(self, username, value):
        cookie_value = make_secure_value(value)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (username, cookie_value))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

# user sign up form
class Signup(BaseHandler):
    def get(self):
        self.render('signup-form.html')

#get form
    def post(self):
        error_flag = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

#save params in dict     
        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()
            

    def done(self, *a, **kw):
        raise NotImplementedError

class Login(BaseHandler):
    def get(self):
        self.render('login-form.html')
        
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        user = User.get_user(username, password)
        if user:
            self.login(user)
            self.redirect('/')
        else:
            self.render('login-form.html', error = 'Invalid Login')


class Logout(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')


# Wiki


class WikiPage(BaseHandler):
    def get(self, location):
        page = Page.all().filter('location =', location).get()

        if not page:
            self.redirect('/_edit' + location)
        else:
            entry = Entry.all().filter('page =', page).order('-timestamp').get()
            params = {'content': entry.content, 'url': location}
            self.render('wiki-page.html', **params)

class EditPage(BaseHandler):
    def get(self, location):
        key = db.Key.from_path('wiki', location)
        self.write(location)
        self.render('wiki-page-form.html')

    def post(self, location):
        content = self.request.get('content')
        entry = Entry.submit(location, content)
        entry.put()
        self.redirect(location)


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=True)