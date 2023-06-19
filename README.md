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
./tools/triage/add_triage_signature.py --help
```

## Triage deep search
* Make sure you are connected to Red Hat VPN (for logs download).

There is now a facility to deep search for issues matching a content regex and a path regex

### Examples

#### Generate a Jira access token

1. Browse to Jira [Personal Access Tokens](https://issues.redhat.com/secure/ViewProfile.jspa?selectedTab=com.atlassian.pats.pats-plugin:jira-user-personal-access-tokens) to Create a new access token. 
2. Configure environment variable:
    ```sh
    export JIRA_ACCESS_TOKEN=<token>
    ```

When using skipper, some characters must be escaped. 
#### Find every ticket containing any file with the phrase "This is a match" in the last 7 days

```sh
skipper run ticket_search --content_search "This is a match" --days=7 --path_search "\(.*\)" > data/reports/must-gather.json
```
Or if you prefer not to escape chars
```sh
skipper shell # (to open a shell)
ticket_search --content_search "This is a match" --days=7 --path_search "(.*)" > data/reports/must-gather.json
```

#### Find every ticket that ends with the word "version" in the last 7 days that has a must gather
```sh
skipper run ticket_search --content_search "openshift/must-gather" --days=7 --path_search "\(.*version$\)" > data/reports/must-gather.json
```
Or if you prefer not to escape chars

```sh
skipper shell # (to open a shell)
ticket_search --content_search "openshift/must-gather" --days=7 --path_search "(.*version$)" > data/reports/must-gather.json
```
### Using the tool via docker or podman directly
```
# Set the appropriate container command
export container_command=docker
# or 
export container_command=podman

# Run this once to build the ticket search container
make build_image

# Run a search like this, you will need to escape chars such as brackets
make ticket_search c="openshift/must-gather" p="\(.version*\)" | jq