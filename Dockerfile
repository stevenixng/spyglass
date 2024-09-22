FROM python:3.8-slim
WORKDIR /spyglass
COPY static/ templates/ spyglass.py requirements.txt /spyglass/
COPY static/ /spyglass/static
COPY templates/ /spyglass/templates

# Upgrade pip and install Python dependencies
RUN pip3 install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Expose port 5000 for the Flask application
EXPOSE 5000

# Define the command to run the Flask application using Gunicorn
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "4", "spyglass:app"]
