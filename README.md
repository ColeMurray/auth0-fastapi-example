# Auth0 FastAPI Demo

A production-ready FastAPI application demonstrating Auth0 Organizations integration for B2B SaaS authentication. This implementation follows security best practices and provides a complete authentication flow suitable for multi-tenant applications.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-009688.svg)](https://fastapi.tiangolo.com)

## Features

- Organization-first authentication flow
- Invitation-based user onboarding
- Role-based access control (Owner, Admin, Member)
- Secure session management with cookies
- Member management (invite, remove, list)

## Installation

### Using pip with pyproject.toml

```bash
# Install the application and its dependencies
pip install -e .

# Install development dependencies
pip install -e ".[dev]"
```

### Using pip directly

```bash
# Install all dependencies
pip install fastapi==0.115.0 uvicorn==0.30.6 httpx==0.27.2 SQLAlchemy==2.0.34 python-jose[cryptography]==3.3.0 pydantic==2.9.1 pydantic-settings==2.3.4

# Install dev dependencies
pip install mypy ruff
```

## Configuration

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Update `.env` with your Auth0 credentials (see `.env.example` for detailed descriptions)

## Auth0 Setup

1. Enable Organizations in your Auth0 tenant
2. Create a Database Connection (Username-Password-Authentication)
3. Create a Regular Web Application with callback URL: `http://localhost:8000/callback`
4. Create a Machine-to-Machine application authorized for the Management API
5. (Optional) Create an API for your access tokens

## Running the Application

```bash
# Run with uvicorn
uvicorn app:app --reload

# The application will be available at http://localhost:8000
```

## Development

### Code Quality

Run linting and type checking:

```bash
# Using the provided script
./lint.sh

# Or run individually
ruff check app.py --fix
mypy app.py
```

### Project Structure

- `app.py` - Main FastAPI application
- `templates/` - HTML templates
  - `index.html` - Login/signup page
  - `dashboard.html` - Organization dashboard
- `.env` - Environment configuration (not in repo)
- `pyproject.toml` - Project configuration and dependencies

## Security Notes

- Uses organization-first flow to prevent information leakage
- Invitation-based onboarding (recommended) prevents unauthorized access
- JWT tokens are verified using JWKS
- Secure HTTP-only cookies for session management
- Role-based access control for member management

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Built With

- [FastAPI](https://fastapi.tiangolo.com/) - Web framework
- [Auth0](https://auth0.com/) - Authentication platform  
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM
- [Pydantic](https://pydantic-docs.helpmanual.io/) - Data validation