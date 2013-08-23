import unittest
from StringIO import StringIO
from main import BaseHandler
from google.appengine.ext.webapp import Request
from google.appengine.ext.webapp import Response
from main import Message

class Test(unittest.TestCase): 
	
	# simulate post request
	
	def test_add_message(self): 
		handler = BaseHandler()
		form = 'msg-hello'
		
		handler.response = Response()

		
		handler.request = Request({'PATH_INFO':'/',\
						'REQUEST_METHOD': 'POST',\
						'wsgi.input': StringIO(form),\
						'CONTENT_LENGTH': len(form)})
		handler.post()
			
	
		message = [m for m in Message.all()] 
		self.failUnless(len(messages) == 1) 