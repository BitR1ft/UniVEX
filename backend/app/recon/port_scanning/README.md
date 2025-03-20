# Port Scanning Module - Quick Reference

## 🚀 Quick Start

### CLI Usage
```bash
# Basic scan
python -m app.recon.port_scanning.cli scan 192.168.1.1

# Hybrid scan with all features
python -m app.recon.port_scanning.cli scan target.com \
  --mode hybrid \
  --service-detection \
  --banner-grab \
  --output results.json

# Passive Shodan scan
python -m app.recon.port_scanning.cli scan 8.8.8.8 --mode passive
```

### API Usage
```bash
# Start scan
curl -X POST http://localhost:8000/api/port-scan/scan \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.1"],
    "mode": "hybrid",
    "service_detection": true,
    "banner_grab": true
  }'

# Check status
curl http://localhost:8000/api/port-scan/status/{task_id} \
  -H "Authorization: Bearer YOUR_TOKEN"

# Get results
curl http://localhost:8000/api/port-scan/results/{task_id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Python Usage
```python
from app.recon.port_scanning import (
    PortScanOrchestrator,
    PortScanRequest,
    ScanMode
)

# Create request
request = PortScanRequest(
    targets=["192.168.1.1"],
    mode=ScanMode.HYBRID,
    service_detection=True,
    banner_grab=True
)

# Run scan
orchestrator = PortScanOrchestrator(request)
result = await orchestrator.run()

# Export
orchestrator.export_json("results.json")
```

## 📚 Features

### Scan Modes
- **Active**: Fast scanning with Naabu (requires root/sudo)
- **Passive**: Intelligence gathering via Shodan (no root required)
- **Hybrid**: Combines both for maximum coverage

### Capabilities
✅ Port scanning (Naabu)
✅ Service detection (Nmap + IANA)
✅ Banner grabbing (raw sockets)
✅ CDN/WAF detection
✅ Shodan passive scanning
✅ Version identification
✅ CPE enumeration
✅ Vulnerability hints

### Configuration Options
- Top-N ports (default: 1000)
- Custom port list
- Port range
- Rate limiting (PPS)
- Thread count
- Timeout settings
- CDN exclusion
- Service detection toggle
- Banner grabbing toggle

## 🧪 Testing

```bash
# Run all tests
cd backend
python -m pytest tests/recon/port_scanning/ -v

# Run specific test
python -m pytest tests/recon/port_scanning/test_cdn_detector.py -v

# Run with coverage
python -m pytest tests/recon/port_scanning/ --cov=app.recon.port_scanning --cov-report=html
```

**Test Status**: ✅ 40/40 passing (100%)

## 📊 Module Structure

```
app/recon/port_scanning/
├── __init__.py           # Exports
├── port_scan.py          # Naabu wrapper (low-level)
├── naabu_orchestrator.py # ✅ NEW – canonical NaabuOrchestrator (Day 28-31)
├── nmap_orchestrator.py  # ✅ NEW – NmapOrchestrator for service detection (Day 33)
├── service_detection.py  # Nmap + IANA
├── banner_grabber.py     # Banner grabbing
├── cdn_detector.py       # CDN detection
├── shodan_integration.py # Shodan API
├── port_orchestrator.py  # Main coordinator
├── schemas.py            # Pydantic models
└── cli.py                # CLI tool
```

## 🔐 Security

✅ **CodeQL Scan**: PASSED (0 vulnerabilities)
✅ **TLS Version**: Minimum TLS 1.2
✅ **Input Validation**: Pydantic V2
✅ **Authentication**: JWT required
✅ **Authorization**: User verification
✅ **Rate Limiting**: Built-in

## 📖 Documentation

- [Month 4 Summary](../MONTH_4_SUMMARY.md)
- [Month 4 Complete Report](../MONTH_4_COMPLETE.md)
- [API Docs](http://localhost:8000/docs) (when backend running)

## 🐛 Troubleshooting

### Naabu not found
```bash
# Install Naabu
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

### Nmap not found
```bash
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap
```

### Permission denied (Naabu SYN scan)
```bash
# Run with sudo or use CONNECT scan
python -m app.recon.port_scanning.cli scan target.com --scan-type connect
```

## 💡 Best Practices

1. **Start with passive scanning** for reconnaissance
2. **Use hybrid mode** for comprehensive results
3. **Enable CDN exclusion** to avoid scanning protected infrastructure
4. **Configure rate limiting** appropriately for your network
5. **Use service detection** for detailed fingerprinting
6. **Export results** for analysis and reporting

## 🎯 Example Workflows

### Reconnaissance
```bash
# Passive scan first
python -m app.recon.port_scanning.cli scan target.com --mode passive -v

# Then targeted active scan on interesting ports
python -m app.recon.port_scanning.cli scan target.com \
  --ports 22,80,443,3306 \
  --service-detection \
  --banner-grab
```

### Comprehensive Scan
```bash
python -m app.recon.port_scanning.cli scan target.com \
  --mode hybrid \
  --top-ports 1000 \
  --service-detection \
  --banner-grab \
  --exclude-cdn \
  --output full_scan.json \
  -v
```

### Quick Port Check
```bash
python -m app.recon.port_scanning.cli scan 192.168.1.1 \
  --ports 80,443 \
  --banner-grab
```

## 📞 Support

- Check inline documentation (docstrings)
- Run `--help` for CLI options
- Review test files for usage examples
- See comprehensive docs in `/docs`

---

**Version**: 1.0  
**Status**: Production Ready ✅  
**Tests**: 40/40 Passing ✅  
**Security**: CodeQL Clean ✅
