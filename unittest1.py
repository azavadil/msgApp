import passwordFn
import validationFn
import unittest

class TestPasswordFunctions(unittest.TestCase):

	
	def test_make_salt1(self):
		salt = passwordFn.make_salt()
		self.assertTrue(len(salt) == 5)

	def test_make_salt2(self):
		salt1  = passwordFn.make_salt()
		salt2  = passwordFn.make_salt()
		self.assertTrue(salt1 != salt2)

	def test_make_pw_hash1(self):
		
		name = 'johndoe'
		pw = 'password'
		salt = '12345'
		
		hash1 = passwordFn.make_pw_hash(name, pw, salt)
		hash2 = passwordFn.make_pw_hash(name, pw, salt)
		
		self.assertTrue(hash1 == hash2)
		
	def test_make_pw_hash2(self):
		
		name = 'johndoe'
		pw = 'password'
		salt = '12345'
		
		hash1 = passwordFn.make_pw_hash(name, pw, salt)
		hash2 = passwordFn.make_pw_hash(name, pw + '1', salt)
		
		self.assertTrue(hash1 != hash2)
	
	def test_make_pw_hash3(self):
		
		name = 'johndoe'
		pw = 'password'
		salt = '12345'
		
		hash1 = passwordFn.make_pw_hash(name, pw, salt)
		hash2 = passwordFn.make_pw_hash(name, pw, salt + '1')
		
		self.assertTrue(hash1 != hash2)

	def test_text_valid_pw(self):
		
		name = 'johndoe'
		pw = 'password'
		hash = '0645ec7e92b01ba7f84c7636cbc3e162a8c9d07ea60ef91ec4b4592fbf637c5d|iOAlW'
		
		self.assertTrue(passwordFn.valid_pw(name, pw, hash))
		
	def test_make_secure_val(self):
		hash = '4ec2a5e8ea740b1b938cc412b3cb3e9a' 
		hashString = 'password|' + hash
		secureVal = passwordFn.make_secure_val('password')
		
		self.assertTrue( secureVal == hashString )
		
	def test_check_secure_val(self): 
		hash = '4ec2a5e8ea740b1b938cc412b3cb3e9a' 
		hashString = 'password|' + hash
		
		self.assertTrue( passwordFn.check_secure_val( hashString ) )
		
def suite(): 
	suite = unittest.TestLoader().loadTestsFromTestCase(TestPasswordFunctions)
	return suite
		
	
if __name__ == '__main__':
    unittest.main()
	