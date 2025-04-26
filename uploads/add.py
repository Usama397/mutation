import unittest

def add(a, b):
    return a + b

def multiply(a, b):
    return a * b

class TestAdd(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_multiply(self):
        self.assertEqual(multiply(2, 5), 10)

if __name__ == "__main__":
    unittest.main()