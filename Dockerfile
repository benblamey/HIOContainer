# Use an official Python runtime as a base image
FROM python:2.7.12

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

# Install any needed packages specified in requirements.txt
RUN pip install urllib3
RUN pip install Pillow
RUN pip install numpy
RUN git clone https://github.com/benblamey/HasteStorageClient.git;cd /app/HasteStorageClient;pip install -e .

# Make port 80 available to the world outside this container
EXPOSE 80

# Run app.py when the container launch
CMD ["python", "function.py"]
