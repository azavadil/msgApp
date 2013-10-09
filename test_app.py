import unittest
import unittest1
import unittest2

suite1 = unittest1.suite()
suite2 = unittest2.suite()
alltests = unittest.TestSuite([suite1, suite2])

if __name__ == '__main__':
	runner = unittest.TextTestRunner()
	runner.run(alltests)
	