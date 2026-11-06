# Use an official Python image
# 3.11: the anthropic SDK (ai_generate.py) needs Python 3.10 or newer. On 3.9
# pip could not resolve it and every image build failed.
FROM python:3.11

# Set the working directory inside the container
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY . .

# Expose the port your server runs on (adjust as needed)
EXPOSE 5000

# Define the command to start your Python app
CMD ["python", "main.py"]

