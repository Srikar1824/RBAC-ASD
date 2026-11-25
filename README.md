# User Authentication System Using JWT

A user authentication REST API built with Node.js, Express.js, Prisma ORM, PostgreSQL, bcrypt, and JSON Web Tokens.

## Stack

| Tool | Purpose |
|---|---|
| Express.js | HTTP server and routing |
| Prisma 7 | ORM for PostgreSQL |
| PostgreSQL | Database |
| bcrypt | Password hashing (10 salt rounds) |
| jsonwebtoken | JWT signing and verification |
| crypto | Unique JWT ID (`jti`) generation |
| dotenv | Environment variable loading |

## Project Structure

```
jwt-auth/
├── app.js                    # Express server and all API routes
├── prisma/
│   └── schema.prisma         # Prisma data model (User)
├── prisma.config.js          # Prisma 7 configuration
├── db/
│   └── config.js             # Prisma client with PrismaPg adapter
├── middleware/
│   └── requireAuth.js        # JWT authentication middleware
├── utils/
│   └── jwt.js                # signToken / verifyToken helpers
├── test.js                   # Automated test suite (node --test)
├── .env.example              # Required environment variable names
└── package.json
```

## Setup

```bash
npm install
cp .env.example .env        # fill in your DB credentials and JWTSECRET
createdb -h localhost -U postgres jwt_auth
npx prisma migrate dev --name init
npm run dev
```

## Environment Variables

```env
DATABASE_URL="postgresql://USER:PASSWORD@localhost:5432/jwt_auth"
JWTSECRET="your-secret-key"
PORT=3000
```

## API Endpoints

| Method | Route | Auth | Description |
|---|---|---|---|
| `POST` | `/signup` | ❌ | Register a new user |
| `POST` | `/login` | ❌ | Log in and receive a JWT |
| `GET` | `/me` | ✅ Bearer | Get the current user's profile |
| `GET` | `/dashboard` | ✅ Bearer | Get a personalised welcome message |

## Running Tests

```bash
npm test
```
