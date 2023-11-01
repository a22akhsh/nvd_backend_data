# Use an official Python runtime as a parent image
FROM python:3.9

# Create a non-root user and group with a specific UID and GID
RUN groupadd -g 1000 myusergroup
RUN useradd -u 1000 -g myusergroup -ms /bin/bash myuser

RUN mkdir /src
# Set permissions for a directory
RUN chmod 777 /src
# Set the working directory
WORKDIR /src

# Copy the current directory contents into the container
COPY --chown=myuser:myuser /src /src
# Switch to the non-root user
USER myuser

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

ENV PYTHONPATH=$PYTHONPATH:/src
# Make port 80 available to the world outside this container
EXPOSE 81

# Define the command to run your application
CMD ["python", "main.py"]