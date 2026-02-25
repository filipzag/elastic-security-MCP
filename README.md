# Elastic Security MCP Server

An MCP server implementation for Elastic Security, allowing creation, enabling, disabling, listing, and templating of detection rules.

## Features

- **List Rules**: Retrieve detection rule summaries (id, name, MITRE TTPs, log source, query type) with automatic pagination and KQL filtering.
- **Get Rule**: Fetch the full details of a single detection rule by ID.
- **Upload Rule**: Create or update detection rules using JSON definitions.
- **Enable Rule**: Enable a specific detection rule.
- **Disable Rule**: Disable a specific detection rule.
- **Get Detection Template**: Returns a predefined EQL detection rule JSON template (APT28 Linux Timestomping) for use as a starting point when creating new rules.

## Prerequisites

- Python 3.12+
- Access to an Elastic Stack (Kibana) instance.

## Installation

1.  Clone the repository:
    ```bash
    git clone <repository-url>
    cd elastic-security-MCP
    ```

2.  Create and activate a virtual environment:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

Set the following environment variables. You can creating a `.env` file in the project root:

```ini
KIBANA_URL=https://your-kibana-url:5601
# Authentication (Choose one method)
ELASTIC_API_KEY=your-api-key
# OR
ELASTIC_USERNAME=your-username
ELASTIC_PASSWORD=your-password
```

## Usage

### Running Locally

Run the server using the compiled Python environment:

```bash
python server.py
```

The server will run on standard input/output (stdio), ready to be connected to an MCP client (like Claude Desktop or a custom client).

### Running with Docker

1.  **Build the image:**
    ```bash
    docker build -t elastic-security-mcp .
    ```

2.  **Run the container:**
    ```bash
    docker run -i --rm \
      -e KIBANA_URL="https://your-kibana-url" \
      -e ELASTIC_API_KEY="your-api-key" \
      elastic-security-mcp
    ```

### Running with Docker Compose

1.  Ensure your `.env` file is configured.
2.  Run:
    ```bash
    docker-compose up --build
    ```

## Testing

Unit tests are included to verify the logic (mocking external API calls).

Run the tests:
```bash
python test_server.py
```
