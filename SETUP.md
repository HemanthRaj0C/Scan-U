# Scan-U Setup and Usage Guide

## Prerequisites

Before running Scan-U, ensure you have the following installed:

- **Python 3.8+**
- **Node.js 16+**
- **Docker & Docker Compose** (for containerized deployment)
- **PostgreSQL 13+** (if running without Docker)
- **Redis 6+** (if running without Docker)
- **Nmap** (for network scanning)

## Installation

### Option 1: Docker Deployment (Recommended)

1. **Clone the Repository**
   ```bash
   git clone https://github.com/HemanthRaj0C/Scan-U.git
   cd Scan-U
   ```

2. **Create Environment File**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and update the following:
   - `SECRET_KEY`: Generate a secure random key
   - `JWT_SECRET_KEY`: Generate a secure random key
   - `NVD_API_KEY`: (Optional) Get free API key from https://nvd.nist.gov/developers

3. **Start Services with Docker Compose**
   ```bash
   docker-compose up -d
   ```

4. **Access the Application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:5000
   - Health Check: http://localhost:5000/health

### Option 2: Manual Installation

#### Backend Setup

1. **Install Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install Nmap**
   - Windows: Download from https://nmap.org/download.html
   - Linux: `sudo apt-get install nmap`
   - macOS: `brew install nmap`

3. **Setup PostgreSQL Database**
   ```bash
   # Create database
   psql -U postgres
   CREATE DATABASE scanu_db;
   CREATE USER scanu WITH PASSWORD 'scanu_password';
   GRANT ALL PRIVILEGES ON DATABASE scanu_db TO scanu;
   ```

4. **Setup Redis**
   ```bash
   # Install and start Redis
   # Linux: sudo apt-get install redis-server
   # macOS: brew install redis
   redis-server
   ```

5. **Create Required Directories**
   ```bash
   mkdir -p logs backend/app/ml/models
   ```

6. **Initialize Database**
   ```bash
   python backend/app/main.py
   # Press Ctrl+C after tables are created
   ```

7. **Run Backend Server**
   ```bash
   # Development
   python backend/app/main.py

   # Production
   gunicorn --bind 0.0.0.0:5000 --workers 4 backend.app.main:app
   ```

#### Frontend Setup

1. **Install Node Dependencies**
   ```bash
   cd frontend
   npm install
   ```

2. **Run Development Server**
   ```bash
   npm run dev
   ```

3. **Build for Production**
   ```bash
   npm run build
   npm run preview
   ```

## Usage Guide

### 1. Creating Your First Scan

1. Navigate to http://localhost:3000
2. Click "New Scan" in the navigation
3. Fill in the scan details:
   - **Target**: IP address, hostname, or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24)
   - **Scan Type**: 
     - Basic: Standard vulnerability scan
     - Aggressive: Comprehensive scan with all Nmap scripts
     - Stealth: Slower but less detectable
   - **Asset Criticality**: Affects risk scoring (Critical, High, Medium, Low)
4. Click "Start Scan"

### 2. Viewing Scan Results

1. Go to "Scans" page to see all scans
2. Click "View Details" on any completed scan
3. Review:
   - Overall risk assessment
   - Vulnerability count by severity
   - False positive rate
   - Detailed vulnerability list with ML risk scores
   - Recommendations

### 3. Analyzing Vulnerabilities

1. Go to "Vulnerabilities" page
2. Use filters:
   - Filter by severity (Critical, High, Medium, Low, Info)
   - Exclude false positives
3. Each vulnerability shows:
   - ML-calculated risk score
   - CVSS score (if available)
   - CVE identifier (if applicable)
   - False positive likelihood
   - Confidence level

### 4. Understanding Risk Scores

Scan-U uses ML-based risk scoring that considers:
- Vulnerability severity
- CVSS score
- Exploitability indicators
- Port exposure
- Asset business criticality
- False positive likelihood

Risk scores range from 0-100:
- 80-100: Critical risk
- 60-79: High risk
- 40-59: Medium risk
- 20-39: Low risk
- 0-19: Minimal risk

## API Usage

### Authentication
Currently, the API is open for development. In production, implement JWT authentication.

### Example API Calls

**Create a Scan:**
```bash
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1",
    "scan_type": "basic",
    "asset_criticality": "high"
  }'
```

**Get Scan Status:**
```bash
curl http://localhost:5000/api/scans/1
```

**List Vulnerabilities:**
```bash
curl "http://localhost:5000/api/vulnerabilities?severity=critical&exclude_fp=true"
```

**Get Dashboard Stats:**
```bash
curl http://localhost:5000/api/dashboard/stats
```

**Lookup CVE:**
```bash
curl http://localhost:5000/api/cve/CVE-2021-44228
```

## Testing

### Run Backend Tests
```bash
pytest tests/
```

### Run with Coverage
```bash
pytest --cov=backend tests/
```

## Troubleshooting

### Nmap Permission Issues
```bash
# Linux: Give nmap capabilities
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

### Database Connection Errors
- Verify PostgreSQL is running: `sudo service postgresql status`
- Check credentials in `.env` file
- Ensure database exists: `psql -U postgres -c "\l"`

### Port Already in Use
```bash
# Find process using port
lsof -i :5000  # Backend
lsof -i :3000  # Frontend

# Kill process
kill -9 <PID>
```

### Docker Issues
```bash
# View logs
docker-compose logs backend
docker-compose logs frontend

# Restart services
docker-compose restart

# Rebuild containers
docker-compose up --build
```

## Security Considerations

### For Production Deployment:

1. **Change Default Secrets**
   - Update SECRET_KEY and JWT_SECRET_KEY
   - Use strong passwords for database

2. **Implement Authentication**
   - Add JWT authentication to API endpoints
   - Implement user management

3. **Network Security**
   - Run behind reverse proxy (Nginx/Apache)
   - Enable HTTPS with SSL certificates
   - Configure firewall rules

4. **Database Security**
   - Use strong database passwords
   - Enable SSL for database connections
   - Regular backups

5. **Scanning Permissions**
   - Only scan authorized targets
   - Implement IP whitelisting
   - Log all scan activities

## Performance Tuning

### For Large-Scale Deployments:

1. **Increase Workers**
   ```bash
   gunicorn --workers 8 --threads 4 backend.app.main:app
   ```

2. **Redis Caching**
   - CVE lookups are cached for 24 hours
   - Adjust cache duration in `cve_lookup.py`

3. **Database Optimization**
   - Add indexes on frequently queried fields
   - Use connection pooling

4. **Concurrent Scans**
   - Adjust `MAX_CONCURRENT_SCANS` in `.env`
   - Monitor system resources

## Maintenance

### Regular Tasks:

1. **Log Rotation**
   ```bash
   # Setup logrotate for logs/scanu.log
   ```

2. **Database Cleanup**
   ```bash
   # Clean old scan data periodically
   psql -U scanu -d scanu_db -c "DELETE FROM scans WHERE started_at < NOW() - INTERVAL '90 days';"
   ```

3. **ML Model Updates**
   - Retrain models periodically with new data
   - Place updated models in `backend/app/ml/models/`

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Support

For issues and questions:
- GitHub Issues: https://github.com/HemanthRaj0C/Scan-U/issues
- Documentation: See README.md

## License

MIT License - See LICENSE file for details
