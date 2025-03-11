# Password API

A secure password management API built with FastAPI and PostgreSQL.

## Features

- User authentication with JWT tokens
- Master user administration
- Password management for websites
- Role-based access control

## Prerequisites

- Docker and Docker Compose
- Git (for cloning the repository)

## Deployment Instructions

### 1. Clone the repository

```bash
git clone <repository-url>
cd PasswordAPI
```

### 2. Build and start the containers

```bash
docker-compose up -d
```

This will:
- Build the Docker image for the API
- Start a PostgreSQL database container
- Connect the two services together
- Expose the API on port 8000

### 3. Accessing the API

Once running, you can access the API at:
- API Documentation: http://localhost:8000/docs

### 4. Creating a master user

To get started, you'll need to create a master user using the `/admin/create-master/` endpoint.

## Environment Variables

The following environment variables can be configured in the `.env` file or in the docker-compose.yml:

- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: Secret key for JWT token generation
- `DB_HOST`: Database hostname
- `DB_PORT`: Database port
- `DB_USER`: Database username
- `DB_PASSWORD`: Database password
- `DB_NAME`: Database name

## Stopping the Service

To stop the API and database:

```bash
docker-compose down
```

To stop the API and database, and also remove all data volumes:

```bash
docker-compose down -v
```

## Development

For local development without Docker, you'll need:
- Python 3.11+
- PostgreSQL

1. Create a virtual environment:
```bash
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up your .env file with the correct database connection details.

4. Run the application:
```bash
uvicorn main:app --reload
``` 