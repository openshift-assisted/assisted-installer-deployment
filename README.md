# assisted-installer-deployment

## Release a new version

You can release a new version by creating a tag in all the assisted-installer repositories.

1. Update the assisted-installer.yaml with the relevant git hash.
2. Build the docker image, locally:

```bash
make local-update
```

3. Execute the release image

```shell script
docker run -v $(pwd)/assisted-installer.yaml:/assisted-installer.yaml -v $HOME/.netrc:/root/.netrc -it assisted-installer-deployment:local -t <tag>
```

## Add new signature

Run the following commands for more details:

```bash
./tools/add_triage_signature.py --help
```
