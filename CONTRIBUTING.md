# Contributing to MakassarScan

First off, thank you for considering contributing to MakassarScan! 🎉

## Code of Conduct

By participating in this project, you are expected to uphold our Code of Conduct:
- Be respectful and inclusive
- Focus on constructive feedback
- Accept criticism gracefully
- Prioritize the community's best interests

## How Can I Contribute?

### 🐛 Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

When creating a bug report, include:
- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Screenshots** if applicable
- **Environment details**:
  - OS (Windows/Linux/macOS)
  - Python version
  - MakassarScan version

### 💡 Suggesting Enhancements

Enhancement suggestions are welcome! Please include:
- **Clear use case** for the feature
- **Expected behavior** description
- **Why this would be useful** to most users
- **Possible implementation** ideas (optional)

### 🔧 Pull Requests

1. **Fork** the repository
2. **Create a branch** for your feature (`git checkout -b feature/amazing-feature`)
3. **Make your changes**
4. **Test thoroughly** on multiple platforms if possible
5. **Commit** with clear messages (`git commit -m 'Add amazing feature'`)
6. **Push** to your branch (`git push origin feature/amazing-feature`)
7. **Open a Pull Request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Makassarscan.git
cd Makassarscan

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt
pip install pytest flake8 mypy black

# Run the application
python app.py
```

## Coding Standards

### Python Style

- Follow **PEP 8** style guide
- Use **type hints** for function parameters and returns
- Write **docstrings** for classes and public functions
- Keep lines under **120 characters**

### Code Quality Tools

```bash
# Format code
black app.py

# Check linting
flake8 app.py

# Type checking
mypy app.py

# Run tests
pytest
```

### Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Keep first line under 72 characters
- Reference issues with `#123` syntax

Examples:
```
Add subdomain enumeration via crt.sh
Fix Windows socket timeout handling (#42)
Update README with CLI examples
```

## Project Structure

```
Makassarscan/
├── app.py              # Main application (GUI + CLI)
├── setup.py            # Package installation
├── requirements.txt    # Dependencies
├── README.md           # Documentation
├── LICENSE             # MIT License
├── CONTRIBUTING.md     # This file
├── .gitignore          # Git ignore patterns
├── .github/
│   └── workflows/
│       └── ci.yml      # GitHub Actions CI
└── assets/             # Images, screenshots
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test
pytest test_scanner.py::test_port_scan
```

### Writing Tests

- Place tests in `test_*.py` files
- Use descriptive test function names
- Test both success and failure cases
- Mock external API calls

## Documentation

- Update README.md for user-facing changes
- Add docstrings for new functions/classes
- Include usage examples for new features
- Update CLI help text if adding options

## Questions?

Feel free to open an issue with the tag `question` if you have any questions about contributing!

---

Thank you for contributing to MakassarScan! 🚀
