# Contributing to Cyntrisec

Thank you for your interest in contributing to Cyntrisec! We welcome contributions from the community to help make cloud security more accessible and effective.

## Development Philosophy

1.  **Safety First**: Cyntrisec is designed to be a **read-only** tool by default. Any code that modifies AWS state must be gated behind explicit user opt-in flags and the `--enable-unsafe-write-mode` global flag.
2.  **Privacy**: We do not send data to external servers. All analysis happens locally.
3.  **Correctness**: Attack paths should be deterministic and verifiable. We prioritize low false positives.

## Environment Setup

Cyntrisec requires Python 3.11 or higher. We recommend using a virtual environment.

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/cyntrisec/cyntrisec.git
    cd cyntrisec
    ```

2.  **Create a virtual environment**:
    ```bash
    python -m venv .venv
    # Windows
    .\.venv\Scripts\activate
    # Linux/MacOS
    source .venv/bin/activate
    ```

3.  **Install dependencies**:
    Install the package in editable mode with development and MCP dependencies:
    ```bash
    pip install -e ".[dev,mcp]"
    ```

## Development Workflow

### Code Style & Linting

We use [Ruff](https://docs.astral.sh/ruff/) for linting and formatting, and [mypy](https://mypy.readthedocs.io/) for static type checking.

```bash
# Run linter
ruff check .

# Fix linting issues automatically
ruff check --fix .

# Run type checker
mypy src
```

### Testing

We use [pytest](https://docs.pytest.org/) for testing. Please ensure all tests pass before submitting a PR.

```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=src

# Run a specific test file
pytest tests/unit/test_graph_builder.py
```

### Project Structure

- `src/cyntrisec/core/`: proper graph logic, schema definitions, and analysis algorithms.
- `src/cyntrisec/aws/`: AWS collectors and data normalization.
- `src/cyntrisec/cli/`: Typer-based CLI interface commands.
- `src/cyntrisec/mcp/`: Model Context Protocol server implementation.
- `tests/`: Unit and integration tests.

## Submitting Changes

1.  **Fork the repository** and create a feature branch.
2.  **Write code** adhering to the style guides.
3.  **Add tests** for your new functionality.
4.  **Run checks**: Ensure `ruff`, `mypy`, and `pytest` all pass.
5.  **Update Documentation**: If you changed CLI commands or logic, update `README.md`.
6.  **Changelog**: Add a note to `CHANGELOG.md` under the `[Unreleased]` section if the change is user-facing.
7.  **Submit a Pull Request**: Describe your changes and the problem they solve.

## Adding New Graph Edges

If you are modifying the capability graph (e.g., adding a new `EdgeKind` or IAM permission):

1.  Update `src/cyntrisec/core/schema.py` if a new enum is needed.
2.  Update `src/cyntrisec/aws/relationship_builder.py` to implement the logic.
3.  **Crucial**: Add a test case in `tests/unit/test_relationship_builder.py` verifying the edge creation and properties.
4.  Verify impact on attack paths by running `pytest tests/integration/test_attack_path_scenarios.py`.

## License

By contributing, you agree that your contributions will be licensed under its Apache License 2.0.
