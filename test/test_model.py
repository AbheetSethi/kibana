import unittest
import requests
import os

BASE_URL = "http://ml-service:5001"
# BASE_URL = "http://192.168.0.102:5001"

class FlaskAppTestCase(unittest.TestCase):

    def test_predict_with_valid_image(self):
        image_path = "img/acne.jpg"
        self.assertTrue(os.path.exists(image_path), "Test image not found.")

        with open(image_path, "rb") as img_file:
            files = {"image": img_file}
            response = requests.post(f"{BASE_URL}/predict", files=files)
            print("Response:", response.status_code, response.text)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("predicted_class", data)

    def test_predict_with_no_image(self):
        response = requests.post(f"{BASE_URL}/predict", files={})
        print("Response:", response.status_code, response.text)
        
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("error", data)

    def test_predict_with_invalid_image(self):
        files = {"image": ("bad.txt", b"not an image")}
        response = requests.post(f"{BASE_URL}/predict", files=files)
        print("Response:", response.status_code, response.text)
        
        self.assertIn(response.status_code, [400, 500])  # depends on your error handling
        data = response.json()
        self.assertIn("error", data)

if __name__ == "__main__":
    unittest.main()
