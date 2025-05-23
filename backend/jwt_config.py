from datetime import timedelta
import os


# JWT_SECRET_KEY = "gK5t8s3Wv9z0Xy2Lm5Np6Qr8Bj7Hu1Ds" 
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
