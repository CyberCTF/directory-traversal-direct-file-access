# Direct File Access - Direct File Access Vulnerability

A file administration portal with a direct file access vulnerability. The application explicitly allows access to sensitive system files.

## Objective
Access sensitive system files directly without bypassing protection.

## Vulnerability
The application allows a access to the `/etc/passwd` file's content.

## Flag
The flag is located in the content of the `/etc/passwd` file. Find it!

## Quick Start

```bash
cd deploy
docker-compose up -d
```

The application will be accessible at http://localhost:3206

## Project Structure

- `build/` - Application source code
- `tests/` - Automated tests
- `deploy/` - Docker configuration
- `docs/` - Documentation

## Tests

```bash
pytest tests/
```

*This is a deliberately vulnerable laboratory designed for educational purposes only.*
