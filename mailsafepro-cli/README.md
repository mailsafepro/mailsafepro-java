# MailSafePro CLI

Command-line interface for [MailSafePro](https://mailsafepro.com) email validation API.

## Installation

```bash
pip install mailsafepro-cli
```

Or install from source:

```bash
git clone https://github.com/mailsafepro/mailsafepro-cli.git
cd mailsafepro-cli
pip install -e .
```

## Quick Start

### 1. Configure API Key

```bash
# Option 1: Environment variable
export MAILSAFEPRO_API_KEY="your-api-key-here"

# Option 2: Save to config file
mailsafepro configure YOUR_API_KEY
```

### 2. Validate Emails

```bash
# Single email
mailsafepro validate user@example.com

# With SMTP check
mailsafepro validate user@example.com --smtp

# JSON output
mailsafepro validate user@example.com --json
```

### 3. Batch Validation

```bash
# From file (one email per line)
mailsafepro batch emails.txt

# Save results to JSON
mailsafepro batch emails.txt -o results.json

# With SMTP verification
mailsafepro batch emails.txt --smtp -o results.json
```

### 4. Check Usage

```bash
mailsafepro usage
```

## Commands

### `validate`

Validate a single email address.

```bash
mailsafepro validate EMAIL [OPTIONS]

Options:
  --smtp / --no-smtp  Check SMTP mailbox (default: no)
  --json              Output as JSON
```

### `batch`

Validate multiple emails from a file.

```bash
mailsafepro batch FILE [OPTIONS]

Options:
  -o, --output FILE   Output file (JSON)
  --smtp / --no-smtp  Check SMTP (default: no)
```

### `usage`

Check API usage and quota.

```bash
mailsafepro usage
```

### `configure`

Save API key to config file.

```bash
mailsafepro configure API_KEY
```

## Examples

### Basic Validation

```bash
$ mailsafepro validate user@gmail.com

Validation: user@gmail.com
┏━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Property     ┃ Value   ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ Valid        │ ✅ Yes  │
│ Risk Score   │ 0.15    │
│ Disposable   │ No      │
│ Provider     │ Gmail   │
└──────────────┴─────────┘

✅ Email is valid
```

### Batch Processing

```bash
$ cat emails.txt
user1@gmail.com
user2@yahoo.com
invalid@fake.com

$ mailsafepro batch emails.txt -o results.json

Found 3 emails to validate
Validating 3 emails... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

✅ Valid: 2/3
❌ Invalid: 1/3
⏱️  Time: 1.23s

Results written to results.json
```

### Check Usage

```bash
$ mailsafepro usage

Usage Statistics
┏━━━━━━━━━━━┳━━━━━━━┓
┃ Metric    ┃ Value ┃
┡━━━━━━━━━━━╇━━━━━━━┩
│ Plan      │ FREE  │
│ Used      │ 45    │
│ Limit     │ 100   │
│ Remaining │ 55    │
│ Usage %   │ 45.0% │
└───────────┴───────┘
```

## Configuration

The CLI looks for configuration in this order:

1. Command-line flags (`--api-key`)
2. Environment variable (`MAILSAFEPRO_API_KEY`)
3. Config file (`~/.mailsafepro/config`)

## Development

```bash
# Clone repo
git clone https://github.com/mailsafepro/mailsafepro-cli.git
cd mailsafepro-cli

# Install in development mode
pip install -e .

# Run tests
pytest tests/
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- Documentation: https://docs.mailsafepro.com
- Issues: https://github.com/mailsafepro/mailsafepro-cli/issues
- Email: support@mailsafepro.com
