# Use an official Python runtime as a base image
FROM python:3.6.3

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

# Install any needed packages specified in requirements.txt
RUN pip install urllib3
RUN pip install Pillow
RUN pip install numpy

# Checkout and install specific version of Haste Storage Client:
RUN git clone https://github.com/benblamey/HasteStorageClient.git;cd /app/HasteStorageClient;git checkout tags/v0.3;pip install -e .

# Make port 80 available to the world outside this container
EXPOSE 80

# Run app.py when the container launch
CMD ["python", "function.py"]
