# test_calculator.py

import unittest
import uploads.calculator  # ✅ Note: 'uploads' prefix because of Flask save location

class TestCalculator(unittest.TestCase):

    def test_add(self):
        self.assertEqual(uploads.calculator.add(2, 3), 5)

    def test_subtract(self):
        self.assertEqual(uploads.calculator.subtract(5, 3), 2)

    def test_multiply(self):
        self.assertEqual(uploads.calculator.multiply(3, 4), 12)

    def test_divide(self):
        self.assertEqual(uploads.calculator.divide(10, 2), 5)

    def test_divide_by_zero(self):
        with self.assertRaises(ValueError):
            uploads.calculator.divide(5, 0)

    def test_is_even(self):
        self.assertTrue(uploads.calculator.is_even(4))
        self.assertFalse(uploads.calculator.is_even(5))

if __name__ == '__main__':
    unittest.main()
