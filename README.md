# OTRUST

![OTRUST Logo](docs/images/logo.png)

**A Protocol for Distributed Truth with Lightweight Blockchain**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D%2014.0.0-brightgreen.svg)](https://nodejs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-%3E%3D%204.4-green.svg)](https://www.mongodb.com/)

## Overview

OTRUST is an innovative distributed verification system that combines cryptographic verification, semantic structuring, and lightweight blockchain technology to create a decentralized fact-checking ecosystem. The system lets users create, confirm and assess claims in a decentralized network where trust is built organically through cryptographically verified interactions.

## Features

- **Cryptographically Verified Claims**: All claims are digitally signed by their creator
- **Semantic Structure**: Claims follow subject-predicate-object format for machine readability
- **Lightweight Blockchain**: Immutability without the performance cost of traditional blockchains
- **Distributed Reputation System**: Users build trust based on the quality of their contributions
- **Proof Chains**: Support for verification, disputation, or invalidation of claims
- **Node Federation**: Synchronization between OTRUST nodes

## Architecture

OTRUST uses a hybrid data architecture:
- **MongoDB**: For fast access to main data
- **Lightweight Blockchain**: For immutable fingerprints of all claims
- **Merkle Trees**: For efficient integrity checking
- **RESTful API**: For integration with client applications

## Prerequisites

- Node.js (v14 or higher)
- MongoDB (v4.4 or higher)
- npm or yarn

## Installation

1. Clone the repository
   ```bash
   git clone https://github.com/otrust-eu/otrust-server.git
   cd otrust-server
   ```

2. Install dependencies
   ```bash
   npm install
   ```

3. Configure environment variables
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. Start the server
   ```bash
   npm start
   ```

For development:
```bash
npm run dev
```

## Docker Deployment

You can also run OTRUST using Docker:

```bash
docker-compose up -d
```

## API Documentation

OTRUST provides a comprehensive REST API:

### Authentication
- `POST /api/auth/register`: Register a new user
- `POST /api/auth/login`: Log in
- `GET /api/auth/verify`: Verify authentication token

### Claims
- `GET /api/claims`: Get all claims with pagination and filtering
- `GET /api/claim/:id`: Get a specific claim
- `POST /api/claim`: Create a new claim
- `PUT /api/claim/:id`: Update an existing claim
- `GET /api/claim/:id/verify`: Verify a claim against the blockchain
- `GET /api/claim/:id/history`: Get the history of a claim

### Proofs
- `POST /api/proof`: Add a proof to a claim

### Users
- `GET /api/user/:pubkey`: Get information about a user
- `PUT /api/user/profile`: Update user profile

### Semantic
- `GET /api/semantic/:subject/:predicate`: Get semantic claims
- `POST /api/semantic/query`: Advanced semantic queries

### Additional endpoints for search, blockchain, statistics, and maintenance are available.

For full API documentation, see [API.md](docs/API.md) or run the server and visit `/api`.

## Development

### Code Structure
- `server.js`: Main application file
- `config/`: Configuration files
- `models/`: MongoDB models
- `routes/`: API routes
- `middleware/`: Express middleware
- `blockchain/`: Lightweight blockchain implementation
- `utils/`: Utility functions

### Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The OTRUST team and contributors
- The open source community

## Links

- [Website](https://otrust.eu)
- [Documentation](https://docs.otrust.eu)
