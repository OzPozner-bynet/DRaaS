# Use an official Python runtime as a parent image
FROM python:3.8

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variable for script name (e.g., producer.py or consumer.py)
ENV SCRIPT_NAME producer.py

# Run the script specified by the environment variable
CMD ["python", "${SCRIPT_NAME}"]
