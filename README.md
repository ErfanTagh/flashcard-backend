# 🚀 Flashcard Backend API

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.2.2-green?style=for-the-badge&logo=flask)
![MongoDB](https://img.shields.io/badge/MongoDB-7.0-green?style=for-the-badge&logo=mongodb)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=for-the-badge&logo=docker)

**A lightweight REST API for a modern flashcard learning platform**

[🔗 Live Website](https://recallcards.net) • [📱 Frontend Repo](https://github.com/ErfanTagh/flashcard-frontend)

</div>

---

## ✨ Features

- 🔐 **Auth0 Integration** - Secure JWT-based authentication
- 📚 **Flashcard Management** - Create, read, update, and delete flashcards
- 🎲 **Random Card Retrieval** - Get random flashcards for review sessions
- 🗄️ **MongoDB Storage** - Scalable document-based database
- 🐳 **Docker Ready** - Containerized deployment with Docker Compose
- 🔄 **CI/CD** - Automated deployment via GitHub Actions
- 🛡️ **CORS Enabled** - Cross-origin resource sharing support

## 🛠️ Tech Stack

| Component          | Technology              |
| ------------------ | ----------------------- |
| **Framework**      | Flask 2.2.2             |
| **Database**       | MongoDB 7.0             |
| **Authentication** | Auth0 (JWT)             |
| **Container**      | Docker & Docker Compose |
| **Deployment**     | GitHub Actions          |

## 📋 API Endpoints

### Authentication Required

All endpoints require a valid JWT token in the `Authorization` header:

```
Authorization: Bearer <your_jwt_token>
```

### Available Endpoints

#### `GET /api/words/rand/<email>`

Get a random flashcard for the specified user.

**Response:**

```json
["term", "definition"]
```

**Error Response:**

```json
["You Don't Have Anything to Memorize ", "Please Add Cards!"]
```

#### `POST /api/sendwords`

Create a new flashcard.

**Request Body:**

```json
{
  "token": "user@example.com",
  "word": "term",
  "ans": "definition"
}
```

**Response:**

```json
{ "status": 200 }
```

#### `DELETE /api/delword/<word>`

Delete a flashcard.

**Request Body:**

```json
{
  "token": "user@example.com"
}
```

**Response:**

```json
{ "status": 200 }
```

#### `POST /api/editword`

Edit an existing flashcard.

**Request Body:**

```json
{
  "token": "user@example.com",
  "oldword": "old_term",
  "word": "new_term",
  "ans": "new_definition"
}
```

**Response:**

```json
{ "status": 200 }
```

#### `POST /api/token`

Validate JWT token (Auth0).

**Response:**

```json
{ "status": 200 }
```

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- MongoDB (or use Docker)
- Docker & Docker Compose (optional)

### Local Development

1. **Clone the repository**

   ```bash
   git clone https://github.com/ErfanTagh/flashcard-backend.git
   cd flashcard-backend
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Set environment variables**

   ```bash
   export MONGO_HOST=localhost
   export MONGO_PORT=27017
   export MONGO_DATABASE=flashcards
   export MONGO_USERNAME=admin
   export MONGO_PASSWORD=password
   ```

4. **Run the server**

   ```bash
   python main.py
   ```

   Server will start on `http://127.0.0.1:5000`

### Docker Deployment

1. **Build and run with Docker Compose**

   ```bash
   docker compose up -d --build
   ```

2. **Check logs**

   ```bash
   docker compose logs -f backend
   ```

3. **Stop services**
   ```bash
   docker compose down
   ```

## 🐳 Docker Setup

The project includes a complete Docker Compose configuration:

```yaml
services:
  mongodb:
    image: mongo:7
    volumes:
      - mongodb_data:/data/db

  backend:
    build: .
    environment:
      - MONGO_HOST=mongodb
      - MONGO_PORT=27017
```

## 🔧 Configuration

### Environment Variables

| Variable         | Description       | Default      |
| ---------------- | ----------------- | ------------ |
| `MONGO_HOST`     | MongoDB host      | `localhost`  |
| `MONGO_PORT`     | MongoDB port      | `27017`      |
| `MONGO_DATABASE` | Database name     | `flashcards` |
| `MONGO_USERNAME` | MongoDB username  | -            |
| `MONGO_PASSWORD` | MongoDB password  | -            |
| `PORT`           | Flask server port | `5000`       |

### Auth0 Configuration

- **Domain**: `dev-43bumhcy.us.auth0.com`
- **Audience**: `recallcards`
- **Algorithm**: `RS256`

## 📦 Project Structure

```
flashcard-backend/
├── main.py              # Flask application and API endpoints
├── requirements.txt     # Python dependencies
├── Dockerfile          # Docker image configuration
├── docker-compose.yml  # Multi-container orchestration
└── README.md           # This file
```

## 🧪 Testing

```bash
# Test random word endpoint
curl http://localhost:5000/api/words/rand/user@example.com

# Test adding a word
curl -X POST http://localhost:5000/api/sendwords \
  -H "Content-Type: application/json" \
  -d '{"token": "user@example.com", "word": "test", "ans": "answer"}'
```

## 🔄 CI/CD

The project uses GitHub Actions for automated deployment:

- **Trigger**: Push to `main` or `master` branch
- **Process**: Pulls latest code, rebuilds Docker containers, restarts services
- **Workflow**: `.github/workflows/deploy.yml`

## 📝 License

This project is open source and available for personal use.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Contact

For questions or issues, please open an issue on GitHub.

---

<div align="center">

**Made with ❤️ for learning**

⭐ Star this repo if you find it helpful!

</div>
