#!/bin/bash
# WordPress Security Scanner Startup Script

echo "Starting WordPress Security Scanner Backend..."

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "Activated virtual environment"
fi

# Set environment variables
export FLASK_APP=app.py
export FLASK_ENV=production

# Start the application
python app.py

echo "WordPress Security Scanner Backend stopped"
