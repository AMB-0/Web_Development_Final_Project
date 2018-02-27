#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#---------------------------------------------------------------------------------#
#                           Imported libraries                                    #
#---------------------------------------------------------------------------------#

import os
import webapp2
import re
import jinja2
import hmac
import hashlib
from google.appengine.ext import db
from google.appengine.api import memcache
import logging
import time
import random
import string

# Jinja2 Enviroment Setting Variables
template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)


#---------------------------------------------------------------------------------#
#                           DataBase Objects Classes                              #
#---------------------------------------------------------------------------------#
class Users(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty(required = False)
	created = db.DateTimeProperty(auto_now_add = True)

class WikiPage(db.Model):
    pathname = db.StringProperty(required = True)
    htmlcode = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    version = db.IntegerProperty(required = True)

#---------------------------------------------------------------------------------#
#                           Base Handler Class                                    #
#---------------------------------------------------------------------------------#

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self,template, **kw):
        self.write(self.render_str(template,**kw))

    # Functions that helps validating cookies
    def hash_str(self,s):
    	secret = "secret_key"
        return hmac.new(secret, s, hashlib.sha256).hexdigest()

    def make_secure_val(self,s):
        return "%s|%s" % (s, self.hash_str(s))

    def check_secure_val(self,h):
        index = h.find('|')
        if self.hash_str(h[0:index]) == h[index+1:len(h)]:
            return h[0:index]
        else:
            return None

    # Functions that helps validating passwords
    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in xrange(5))

    def make_pw_hash(self,name, pw, salt=''):
        if not (salt):
            salt = self.make_salt()
    	h = hashlib.sha256(name + pw + salt).hexdigest()
    	return '%s|%s' % (h, salt)

    def valid_pw(self,name, pw, h):
        salt = h.split('|')[1]	
    	if h == self.make_pw_hash(name,pw,salt):
        	return True

    # Functions that helps retrieving an existing wikipage
    def get_all_wikipage(self, pathname="", update = False):
        wikipage = memcache.get(pathname)
        if wikipage is None or update:
            wikipage = db.GqlQuery("SELECT * FROM WikiPage WHERE pathname=:1 ORDER BY created DESC", pathname)
            memcache.set(pathname, wikipage)
        return list(wikipage)

    def get_current_wikipage(self,pathname=""):
        if self.get_all_wikipage(pathname):
            return self.get_all_wikipage(pathname)[0]

    def get_wikipage_by_version(self,pathname="", version=""):
        wikipage = self.get_all_wikipage(pathname)
        for wiki in wikipage:
            if wiki.version == version:
                return wiki

    def wikipage_exists(self, pathname=""):
        if self.get_all_wikipage(pathname):
            return True
        else:
            return False


#---------------------------------------------------------------------------------#
#                           Wiki Classes                                          #
#---------------------------------------------------------------------------------#

#-------------#
# (1) LOGIN:  #
#-------------#
class Login(Handler):
    # Function that returns True if the username exists in the database(False otherwise)
    def verify_username_exist(self,username=""):
        result = db.GqlQuery("SELECT * FROM Users WHERE username = :1", username)
        if result.get():
            return True
        else:
            return False

    # Function that returns True if users password is correct (False otherwise)
    def verify_username_password(self,username="",password=""):
        result = db.GqlQuery("SELECT * FROM Users WHERE username = :1", username)
        h = result.get().password
        if self.valid_pw(username,password,h):
            return True
        else:
            return False

    # Get Function for Login. Is called when a browser sends a GET HTTP method for the login page
    def get(self):
        self.render("login.html")

    # Post Function for Login. Is called when a browser sends a POST HTTP method for the login page
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        # We set the value of the error messages and the error variable
        error = False
        user_error_msg = "" 
        pass_error_msg = "" 

        # We check if the entered username exists in the database. if the user doesn't exist, we set an error flag and set the error message
        if not self.verify_username_exist(username):
            error = True
            user_error_msg = "User doesnt exist. Please signup first"
        # We check if the entered password is the right one for the entered username. if the password is wrong, we set an error flag and set the error message
        elif not self.verify_username_password(username,password):
            error = True
            pass_error_msg = "Wrong Password"

        # If any error occurs, we render the login page with the corresponding error message. If everything is OK, we login the user and redirect the user to the wiki mainpage
        if error == True:
            self.render("login.html",user = username, user_error_msg = user_error_msg, pass_error_msg = pass_error_msg)
        else:
            self.response.headers.add_header('Set-Cookie','user_name=%s; Path=/' % str(self.make_secure_val(username)))
            self.redirect("/wiki/")

#--------------#
# (2) LOGOUT:  #
#--------------#
class Logout(Handler):
    # Get Function for Logout. Erase the cookies and redirect to the main wiki page
    def get(self):
        if self.request.cookies.get('user_name'):
            self.response.headers.add_header('Set-Cookie', 'user_name=; Path=/')
        self.redirect('/wiki/')


#--------------------#
# (3) SIGNUP PAGE:   #
#--------------------#
class Signup(Handler):
    def render_page(self, username_error="", password_error="", verify_error="", email_error="", user=""):
        self.render("signup.html", username_error = username_error,  password_error = password_error, verify_error = verify_error,email_error = email_error,user = user)

    # Method that verifies that the given username, satisfy the username constrains
    def verify_username(self, username=""):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(username)

    # Method that verifies that the given password, satisfy the password constrains
    def verify_password(self, password=""):
        PASS_RE = re.compile(r"^.{3,20}$")
        return PASS_RE.match(password)

    # Method that verifies that the given e-mail, satisfy the e-mail constrains
    def verify_email(self, email=""):
        MAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        return MAIL_RE.match(email)

    # Method that verifies that the given username, already exists in the application
    def verify_user_already_exist(self, username=""):
        cursor = db.GqlQuery("SELECT * FROM Users WHERE username=:1", username.lower())
        if cursor.get():
        	return True
        else:
        	return None

    # Get Function for Signup. Is called when a browser sends a GET HTTP method for the signup page. This methods calls the render page method
    def get(self):
        self.render_page()

    # Post Function for Signup. Is called when a browser sends a POST HTTP method for the signup page.
    def post(self):
        # First, we get every parameter sent by user
        username = self.request.get("username")
        password = self.request.get("password")
        verify_password = self.request.get("verify")
        email = self.request.get("email")

        # We set the value of the error messages
        user_error = ""
        pass_error = ""
        verify_pass_error = ""
        email_error = ""

		# We set the value of the error variable
        error = False

        # We check if username structure is correct
        if not self.verify_username(username):
            user_error = "Invalid username"
            error = True

        # We check that password structure is correct and also that both password entered match
        if not self.verify_password(password):
            pass_error = "Invalid Password"
            error = True
        elif password != verify_password:
            verify_pass_error = "Password didn't match"
            error = True

        # We check if email structure is correct
        if not self.verify_email(email) and len(email)>0:
            email_error = "Invalid E-Mail"
            error = True

		# We check that username doesn't already exist
        if self.verify_user_already_exist(username):
            user_error = "UserName Already Exist"
            error = True

        # If any error occurs, we render again the page with the error. If everything is fine, we create the user and redirect the user to the wiki mainpage
        if error == True:
            self.render_page(user_error,pass_error,verify_pass_error,email_error,username)
        else:
            new_user = Users(username = username.lower(), password = self.make_pw_hash(username,password), email = email)
            new_user.put()
            self.response.headers.add_header('Set-Cookie','user_name=%s; Path=/' % str(self.make_secure_val(username)))
            self.redirect("/wiki/")



#-----------------------#
# (4) EDIT PAGE   :    #
#-----------------------#
class EditPage(Handler):
    # This codes applies when a user creates a new page or edit a existing one. 
    # First we check if user is log in. If not, we redirect the user to login page.
    # If user is log in, we render the current version of the wikipage in edit mode

    # Get Function for Edit Page.
    def get(self, new_url):
        # Check if the user has already login in the website
        name = self.check_secure_val(str(self.request.cookies.get('user_name')))
        # If not, we redirect the user to the login URL
        if not name:
            self.redirect("/wiki/login")
        else:
            if self.request.get("v"):
                wikipage = self.get_wikipage_by_version(new_url, int(self.request.get("v")))
            else:
                wikipage = self.get_current_wikipage(new_url)
            self.render("edit_page.html", username = name, wikipage = wikipage, show_edit = False, show_history = False)

    # Post Function for Signup.
    def post(self, new_url):
        # We retrieve the html code sent in the HTML form
        htmlcode = self.request.get("content")
        pathname = new_url
        # We set the version variable of the wikipage
        if self.wikipage_exists(pathname):
            version = int(self.get_current_wikipage(pathname).version) + 1
        else:
            version = 0
        # We create the Wikipage object and inserts it in the databse
        a = WikiPage(pathname = str(pathname), htmlcode = str(htmlcode), version = version)
        key = a.put()
        wikipage = self.get_all_wikipage(pathname, True)
        # Sleep 1 second. This prevents that a user is redirect to the wiki page before the database is actually updated
        time.sleep(1)
        # After inserting the wikipage in database, we redirect the user to the wikipage
        self.redirect("/wiki" + str(pathname))


#-----------------------#
# (5) WIKI PAGE:   #
#-----------------------#
class WikiPageHandler(Handler):
    # This codes applies for the wiki pages. If user visits a page that already exist, we render the page with the proper header.
    # If the page doesn't exist, we redirect user to a page where we can edit or create the page
    def get(self, new_url):
        # In case that wikipage exists, we render the current version of the wikipage or one of the older versions of the page according to 
        # the user parameters. If wikipage doesn't exist, we redirect the user to an edit page of the wikipage
        if self.wikipage_exists(new_url):
            # Get name of the user in case that he has already login in the website
            name = self.check_secure_val(str(self.request.cookies.get('user_name')))
            # Get the 'v' parameter in case that user has include one. This works in case that user wants to retrieve any older versions of the wiki page
            if self.request.get("v"):
                # Get the wikipage according to the version requested by the user and sets a history flag in True (history flag helps us to know when to include version parameter in URL)
                wikipage = self.get_wikipage_by_version(new_url,int(self.request.get("v")))
                history_flag = True
            else:
                # Get the current version of the wikipage and sets a history flag in False (history flag helps us to know when to include version parameter in URL)
                wikipage = self.get_current_wikipage(new_url)
                history_flag = False
            self.render("wikipage.html", username = name, wikipage = wikipage, show_edit = True, show_history = True, history_flag = history_flag)
        else:
            self.redirect('/wiki/_edit' + new_url)


#-----------------------#
# (6) WIKI HISTORY  :   #
#-----------------------#
class HistoryHandler(Handler):
    # This codes applies when user wants to see the history version of some wikipages
    def get(self, new_url):
         # Check if the user has already login in the website, if not, we redirect the user to the login URL
        name = self.check_secure_val(str(self.request.cookies.get('user_name')))
        if not name:
            self.redirect("/wiki/login")
        else:
            wikipage = self.get_all_wikipage(new_url)
            self.render("wikipage_history.html", username = name, wikipage = wikipage, show_edit = False, show_history = False)

#---------------------------------------------------------------------------------#
#                           ALL WEBSITE HANDLERS                                  #
#---------------------------------------------------------------------------------#

# Regular expression that represents any page a user can create in the wiki
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'  

# Website Handlers
app = webapp2.WSGIApplication([
    ('/wiki/signup', Signup),                       # Signup Handler
    ('/wiki/login', Login),                         # Login Handler
    ('/wiki/logout', Logout),                       # Logout Handler
    ('/wiki/_edit' + PAGE_RE, EditPage),            # Edit Handler
    ('/wiki/_history' + PAGE_RE, HistoryHandler),   # History Handler
    ('/wiki' + PAGE_RE, WikiPageHandler),           # WikiPage Handler
], debug=True)
