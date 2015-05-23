import os
import re
import random
import hmac
import hashlib
import logging
import json
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'WAHAHAHA'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BasicHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **kw):
        kw['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(kw)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, cookieName, val):
        secure_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s' % (cookieName, secure_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=')

    def initialize(self, *a, **kw):
        print 'hi'
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BasicHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "Invalid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Invalid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Passwords didn't match"
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "Invalid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'This username already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class Login(BasicHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login.'
            self.render('login-form.html', error = msg)

class Logout(BasicHandler):
    def get(self):
        self.logout()
        self.redirect('/')

##### wiki stuff

def post_key(name = 'default'):
    return db.Key.from_path('posts', name)

class Post(db.Model):
    urlname = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    def as_dict(self):
        time_fmt = '%c'
        d = {'urlname': self.urlname,
             'content': self.content,
             'created': self.created.strftime(time_fmt)}
        return d

    @classmethod
    def by_id(cls, pid):
        return Post.get_by_id(pid, parent = post_key())

    @classmethod
    def by_urlname(cls, urlname):
        p = Post.all().ancestor(post_key()).filter('urlname =', urlname)
        return p

    @classmethod
    def newest_by_urlname(cls, urlname):
        p = Post.all().ancestor(post_key()).filter('urlname =', urlname).order('-created').get()
        return p

class EditPage(BasicHandler):
    def get(self, page_re):
        if self.user:
            print 'page_re', page_re
            urlname = '/' if page_re == '/' else page_re.split('/')[1]
            p = Post.newest_by_urlname(urlname)
            if p:
                self.render("edit.html", content = p.content)
            else:
                self.render("edit.html")
        else:
            self.redirect(page_re)

    def post(self, page_re):
        if self.user:
            content = self.request.get('content')
            urlname = '/' if page_re == '/' else page_re.split('/')[1]
            if content:
                p = Post(parent = post_key(),
                         urlname = urlname,
                         content = content)
                p.put()
                self.redirect(page_re)
            else:
                self.redirect(page_re)
        else:
            self.redirect(page_re)

class WikiPage(BasicHandler):
    def get(self, page_re):
        urlname = '/' if page_re == '/' else page_re.split('/')[1]
        p = Post.newest_by_urlname(urlname)
        print 'urlname', urlname
        if p:
            self.render("front.html", post = p, edit=page_re)
        else:
            self.redirect('/_edit' + page_re)

#class MainPage(BasicHandler):
#    def get(self):
#        self.render("base.html")



PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
                              #('/', MainPage),
                              ('/signup/?', Signup),
                              ('/login/?', Login),
                              ('/logout/?', Logout),
                              ('/_edit' + PAGE_RE, EditPage),
                              (PAGE_RE, WikiPage)
                              ], debug=True)
