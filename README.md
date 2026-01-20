# GraphQL Login System

A Authentication & Authorization system built with Python, Strawberry GraphQL, SQLite, and Redis.

## Features

- **GraphQL API**: Schema defined using Strawberry.
- **Authentication**: JWT-based (Access & Refresh Tokens).
- **MFA Support**: Time-based One-Time Password (TOTP) using `pyotp`.
- **Policies**: Organization-level login policies (SSO, MFA, etc.).
- **Security**: IP Restriction logic per organization.
- **Observability**: Request Tracing via `X-Correlation-ID`.
- **Frontend Tester**: Simple HTML/JS client (`index.html`) for testing flows.

## Prerequisites

- Python 3.9+
- Redis Server (must be running on localhost:6379 - default port)

## Setup

1.  Create a virtual environment:
    ```bash
    python -m venv venv
    .\venv\Scripts\activate  # Windows
    source venv/bin/activate  # Mac/Linux
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3.  Initialize the Database:
    ```bash
    python setup_db.py
    ```
    *This creates `data.db` (SQLite) and seeds `localhost` Redis with dummy organization data.*

## Running the Server

Start the server using:

```bash
python server.py
```

The server runs on `http://0.0.0.0:8000`.

## Testing

### Manual Testing (Recommended)
**The primary way to test this application is using the `index.html` file.**

1. Ensure the server is running.
2. Open `index.html` in your web browser.
3. Use the pre-configured buttons to test various scenarios:

- **Normal Login**: `user@normal.com`
- **MFA Login**: `user@mfa.com` (Requires 2-step verification)
- **MFA Missing**: `user@mfa-missing.com` (Demonstrates error handling for missing MFA)
- **Blocked IP**: `user@blocked.com` (Demonstrates IP restriction)

The `index.html` dashboard provides a clear view of the GraphQL requests and responses.


## Project Structure

- **`server.py`**: Main application entry point. Defines the GraphQL Schema (`Mutation.login`), Request Middleware, and App setup.
- **`helper.py`**: Contains DB access, Token generation, Validation utilities, and Redis helpers.
- **`setup_db.py`**: Script to seed SQLite and Redis with test data.
- **`index.html`**: Frontend test ui.
