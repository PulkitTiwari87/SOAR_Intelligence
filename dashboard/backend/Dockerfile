# SOAR Backend Dockerfile
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

# Expose API port
EXPOSE 3000

# Start the server
CMD ["npm", "start"]
