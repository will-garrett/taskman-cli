# Task Manager CLI

```
""8""                      8""8""8                                     
  8   eeeee eeeee e   e    8  8  8 eeeee eeeee eeeee eeeee eeee eeeee  
  8e  8   8 8   " 8   8    8e 8  8 8   8 8   8 8   8 8   8 8    8   8  
  88  8eee8 8eeee 8eee8e   88 8  8 8eee8 8e  8 8eee8 8e    8eee 8eee8e 
  88  88  8    88 88   8   88 8  8 88  8 88  8 88  8 88 "8 88   88   8 
  88  88  8 8ee88 88   8   88 8  8 88  8 88  8 88  8 88ee8 88ee 88   8 
```

This is a simple Python "refresher project" for my enrollment in an AI/ML training course.

A secure command-line task management application built with Python that features quantum-resistant encryption and advanced security measures for task storage and user authentication.

## Features

- 🛡️ Argon2 password hashing
- 🔐 Advanced encryption for task storage using AES-256
- 🧮 Memory-hard key derivation with PBKDF2
- 👥 Multi-user support with isolated task encryption
- ✨ Beautiful CLI interface with colored output
- 📋 Complete task management functionality

## Installation & Setup

### Option 1: Using uv (Recommended)

1. Install uv if not already installed:
```bash
# On Unix/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

2. Install project and dependencies:
```bash
# This will automatically create a venv and install all dependencies from pyproject.toml
uv sync
```

### Option 2: Using pip (Traditional Method)

1. Create and activate a virtual environment:
```bash
# Create virtual environment
python -m venv venv

# Activate on Unix/macOS
source venv/bin/activate

# Activate on Windows
venv\Scripts\activate
```

2. Install project and dependencies:
```bash
pip install .
```

## Running the Application

### Method 1: Using uv (Recommended)
```bash
# No need to activate virtual environment or install separately
uv run task-manager.py
```

### Method 2: Using Python directly
```bash
# Make sure your virtual environment is activated
python task-manager.py
```

## Usage

### Available Commands

1. **Register** - Create a new user account
2. **Login** - Access your tasks with your credentials
3. **Add Task** - Create a new task
4. **View Tasks** - Display all your tasks with their status
5. **Mark Task as Completed** - Update task status
6. **Delete Task** - Remove a task
7. **Logout** - Securely end your session

## Security Features

### Password Protection
- **Argon2 Password Hashing**: Industry-leading memory-hard password hashing
  - 16 iterations for computational complexity
  - 64MB memory usage to resist parallel attacks
  - 2 parallel threads for enhanced performance
  - 32-byte hash length for strong security
  - 32-byte unique salt per user

### Task Encryption
- **AES-256 Encryption**: Military-grade encryption for all tasks
- **Unique Per-User Salt**: 32-byte random salt for each user's task encryption
- **Strong Key Derivation**: PBKDF2 with 1,000,000 iterations
- **Secure Random Number Generation**: Using Python's `secrets` module for cryptographic operations

### Additional Security Measures
- **Memory-Hard Operations**: Resistant to hardware-accelerated attacks
- **Zero Plaintext Storage**: All sensitive data is encrypted or hashed
- **Secure Password Input**: Hidden password entry using getpass
- **Session Management**: Secure logout with memory clearing

## Data Storage

The application uses two encrypted JSON files:
- `users.json` - Stores:
  - Argon2 password hashes
  - Unique encryption salts
  - User metadata
- `tasks.json` - Stores:
  - AES-256 encrypted tasks
  - Encrypted task metadata
  - User-specific task collections

## Security Notes

- All encryption keys are derived from user passwords and never stored
- Each user's tasks are encrypted with unique keys
- The system is designed to be resistant to:
  - Rainbow table attacks
  - Brute force attempts
  - Quantum computing threats
  - Memory-based attacks

## License

This project is licensed under the MIT License - see the LICENSE file for details.
