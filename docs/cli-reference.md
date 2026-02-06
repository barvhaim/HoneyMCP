# CLI Reference

HoneyMCP includes a command-line tool for setup and management.

## Initialize Configuration

```bash
honeymcp init [--directory DIR] [--force]
```

Creates `honeymcp.yaml` and `.env.honeymcp` in the target directory.

Options:
- `-d, --directory` - Target directory (default: current directory)
- `-f, --force` - Overwrite existing files

## Show Version

```bash
honeymcp version
```

## Generate a New Tool

```bash
honeymcp create-tool "dump container registry credentials"
```
