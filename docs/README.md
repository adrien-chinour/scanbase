# ScanBase Documentation

Welcome to the ScanBase documentation. This directory contains comprehensive documentation to help you understand, set up, develop, and maintain the ScanBase project.

## Documentation Index

- **[Overview](./01-overview.md)** - Project overview, goals, and key concepts
- **[Architecture](./02-architecture.md)** - System architecture, design patterns, and component structure
- **[Database Schema](./03-database.md)** - Database schema, tables, relationships, and indexes
- **[API Reference](./04-api.md)** - Complete API endpoint documentation
- **[Setup Guide](./05-setup.md)** - Installation, configuration, and deployment instructions
- **[Development Guide](./06-development.md)** - Development workflow, code organization, and best practices
- **[Features](./07-features.md)** - Detailed feature documentation and usage guides
- **[Security](./08-security.md)** - Security considerations, authentication, and data protection

## Quick Start

1. Read the [Overview](./01-overview.md) to understand what ScanBase does
2. Follow the [Setup Guide](./05-setup.md) to get started
3. Review the [Architecture](./02-architecture.md) to understand the system design
4. Check the [API Reference](./04-api.md) for integration details

## Project Summary

ScanBase is a web application for managing Software Bill of Materials (SBOMs) and tracking security vulnerabilities across dependencies. It integrates with GitHub to fetch SBOMs and OSV.dev to check for vulnerabilities.

**Key Features:**
- Scan GitHub repositories to extract SBOMs
- Track dependencies across multiple repositories
- Check vulnerabilities using OSV.dev API
- Search dependencies across all scanned repositories
- Custom vulnerability and deprecation rules
- Persistent storage with SQLite
- GitHub OAuth authentication

**Tech Stack:**
- Backend: Node.js v24, Express.js
- Database: SQLite (better-sqlite3)
- Frontend: Alpine.js, vanilla JavaScript
- APIs: GitHub API, OSV.dev API

## Contributing

When contributing to ScanBase, please:
1. Follow the code organization patterns described in [Development Guide](./06-development.md)
2. Review the [Architecture](./02-architecture.md) to understand system design
3. Check the [Database Schema](./03-database.md) before making schema changes
4. Update relevant documentation when adding features

