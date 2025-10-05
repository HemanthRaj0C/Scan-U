#!/bin/bash

echo "======================================"
echo "Scan-U Setup Script"
echo "======================================"

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "✓ .env file created. Please update with your configuration."
else
    echo "✓ .env file already exists"
fi

# Create logs directory
if [ ! -d logs ]; then
    echo "Creating logs directory..."
    mkdir -p logs
    echo "✓ logs directory created"
else
    echo "✓ logs directory already exists"
fi

# Create ML models directory
if [ ! -d backend/app/ml/models ]; then
    echo "Creating ML models directory..."
    mkdir -p backend/app/ml/models
    touch backend/app/ml/models/.gitkeep
    echo "✓ ML models directory created"
else
    echo "✓ ML models directory already exists"
fi

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install -r requirements.txt
echo "✓ Python dependencies installed"

# Install Node dependencies
if [ -f package.json ]; then
    echo ""
    echo "Installing Node.js dependencies..."
    npm install
    echo "✓ Node.js dependencies installed"
fi

echo ""
echo "======================================"
echo "Setup complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "1. Update .env file with your configuration"
echo "2. Make sure PostgreSQL and Redis are running"
echo "3. Run 'python backend/app/main.py' to start the backend"
echo "4. Run 'npm run dev' in the frontend directory to start the frontend"
echo ""
echo "Or use Docker:"
echo "  docker-compose up -d"
echo ""
