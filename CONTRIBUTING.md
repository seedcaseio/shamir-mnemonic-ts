# Contributing to Shamir Mnemonic TypeScript

Thank you for your interest in contributing to this project! We welcome contributions from the community and are grateful for your help in making this project better.

## How to Contribute

There are several ways you can contribute to this project:

### Reporting Bugs

If you find a bug, please open an issue on GitHub with:
- A clear description of the bug
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Your environment (Node.js version, OS, etc.)
- Any relevant error messages or logs

### Proposing Features

We welcome feature proposals! Please open an issue to discuss:
- The use case for the feature
- How it would benefit users
- Any implementation ideas you have

### Submitting Pull Requests

Pull requests are the best way to contribute code changes. Please follow the process outlined below.

## Development Setup

### Prerequisites

- Node.js >= 18.0.0
- npm (comes with Node.js)

### Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/shamir-mnemonic-ts.git
   cd shamir-mnemonic-ts
   ```

3. Install dependencies:
   ```bash
   npm install
   ```

4. Build the project:
   ```bash
   npm run build
   ```

5. Run tests to ensure everything works:
   ```bash
   npm test
   ```

### Project Structure

- `src/` - Source TypeScript files
  - `constants.ts` - SLIP-0039 constants
  - `utils.ts` - Utility functions and error classes
  - `wordlist.ts` - Wordlist management
  - `rs1024.ts` - RS1024 checksum implementation
  - `cipher.ts` - Feistel cipher for encryption/decryption
  - `share.ts` - Share encoding/decoding
  - `shamir.ts` - Core Shamir secret sharing algorithms
  - `recovery.ts` - Interactive recovery state management
  - `index.ts` - Public API exports
- `tests/` - Test files
- `dist/` - Compiled JavaScript output (generated)

## Code Standards

### TypeScript Style

- Follow the existing code style in the project
- Use TypeScript strict mode conventions
- Prefer explicit types over `any`
- Use meaningful variable and function names
- Keep functions focused and single-purpose

### Code Formatting

- Maintain consistency with existing code formatting
- Use 2 spaces for indentation
- Follow the existing naming conventions (camelCase for variables/functions, PascalCase for classes)

### Comments and Documentation

- Add JSDoc comments for public functions
- Explain complex algorithms or non-obvious code
- Keep comments up-to-date with code changes

### Tests

- All new features must include tests
- Tests should cover both success and error cases
- Maintain or improve test coverage
- Run `npm test` before submitting

## Pull Request Process

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes**:
   - Write clean, well-documented code
   - Follow the code standards above
   - Add tests for new functionality
   - Update documentation if needed

3. **Ensure tests pass**:
   ```bash
   npm test
   npm run test:vectors
   ```

4. **Build the project** to ensure it compiles:
   ```bash
   npm run build
   ```

5. **Commit your changes**:
   - Use clear, descriptive commit messages
   - Reference related issues in commit messages (e.g., "Fix #123")

6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Open a Pull Request** on GitHub:
   - Provide a clear description of your changes
   - Reference any related issues
   - Explain why the change is needed
   - Include any breaking changes or migration notes

### Pull Request Guidelines

- Keep PRs focused and reasonably sized
- One feature or fix per PR
- Ensure all CI checks pass
- Be responsive to review feedback
- Update your PR if requested

## Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run test vectors
npm run test:vectors
```

### Writing Tests

- Place test files in the `tests/` directory
- Use descriptive test names
- Test both positive and negative cases
- Ensure tests are deterministic and don't rely on external state

### Test Coverage

- Aim to maintain or improve test coverage
- New code should have corresponding tests
- Critical paths (like cryptographic operations) should have comprehensive tests

## Important Notes

### SLIP-0039 Compatibility

This project implements the SLIP-0039 standard. When making changes:

- **Maintain binary compatibility** with the SLIP-0039 specification
- **Do not break** existing mnemonic format compatibility
- **Test thoroughly** with the provided test vectors
- **Document** any deviations or extensions to the standard

### Security Considerations

This project handles cryptographic operations. Please:

- Be extra careful with security-related changes
- Review cryptographic code thoroughly
- Consider security implications of any changes
- Report security issues privately if needed

## Getting Help

If you need help or have questions:

- Open an issue on GitHub for questions
- Check existing issues and discussions
- Review the README.md for usage examples

## Code of Conduct

Please be respectful and constructive in all interactions. We aim to maintain a welcoming and inclusive community.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Shamir Mnemonic TypeScript!
