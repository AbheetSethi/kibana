# Use official Node image
FROM node:18

# Set working directory
WORKDIR /app

# Copy package.json and install dependencies
COPY package.json package-lock.json ./
RUN npm install

# Copy environment file
COPY .env .env

# Copy rest of the frontend code
COPY . .

# Log env var
RUN echo "✅ Environment variable:" && grep REACT_APP_API_URL .env

# Build the React app
RUN npm run build

# Serve the React app using serve
RUN npm install -g serve
CMD ["serve", "-s", "build", "-l", "3000"]
