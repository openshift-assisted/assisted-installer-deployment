# assisted-installer-deployment

## Release a new version

You can release a new version by creating a tag in all the assisted-installer repositories.
1. Update the assited-installer.yaml with the relevant git hash.
1. Execute the release image

```shell script
docker run -v $(pwd)/assited-installer.yaml:/assited-installer.yaml -v $(HOME)/.netrc:/root/.netrc -it assisted-installer-deployment:latest -t <tag>
```