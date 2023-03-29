# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Expose the port that the app runs on
EXPOSE 8000

# Run the app
CMD ["uvicorn", "sql_app.main:app", "--host", "0.0.0.0", "--port", "80"]
