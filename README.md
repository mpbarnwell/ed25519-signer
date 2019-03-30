# Ed25519 Signer

Signs input data using an Ed25519 key and EdDSA.

## Usage

```
usage: java -jar ed25519-signer-1.0-SNAPSHOT.jar [-h] [-k KEY] [-i [IN]]

Calculates signatures using EdDSA and Ed25519

named arguments:
  -h, --help             show this help message and exit
  -k KEY, --key KEY      Key file
  -i [IN], --in [IN]     Input data file, defaults to stdin (default: stdin)
```

## Build

```bash
mvn clean package
```

## License

Apache License, Version 2.0