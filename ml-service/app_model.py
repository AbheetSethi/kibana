from flask import Flask, request, jsonify
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
import numpy as np
import os
from io import BytesIO

app = Flask(__name__)

# Load the trained model
model = load_model("trained_model.h5")

# Set your class labels (match training order)
class_labels = ['Enfeksiyonel', 'Ekzama', 'Acne', 'Pigment', 'Benign', 'Malign']

# Image preprocessing function
def preprocess_image(file):
    try:
        img = image.load_img(BytesIO(file.read()), target_size=(128, 128))  # Read into memory
        img_array = image.img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = img_array / 255.0
        return img_array
    except Exception as e:
        raise ValueError(f"Image preprocessing failed: {e}")


@app.route("/predict", methods=["POST"])
def predict():
    if 'image' not in request.files:
        return jsonify({"error": "No image uploaded"}), 400
    
    file = request.files['image']
    try:
        img_array = preprocess_image(file)
        prediction = model.predict(img_array)
        predicted_index = np.argmax(prediction, axis=1)[0]
        predicted_class = class_labels[predicted_index]
        # confidence = float(np.max(prediction)) * 100

        return jsonify({
            "predicted_class": predicted_class
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True) 
