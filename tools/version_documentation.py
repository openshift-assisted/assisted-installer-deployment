import subprocess
import argparse
import logging
import shutil
import os
import re

logging.basicConfig(format='%(asctime)s %(message)s')
logging.getLogger().setLevel(logging.INFO)

REPO_URL_TEMPLATE = "https://github.com/openshift/{}.git"
valid_commit_regex = '^([A-Z]+-[0-9]+|#[0-9]+|merge|no-issue)'

############################################################################################
# This is used to generate the documentation of assisted-service between different versions.
############################################################################################

parser = argparse.ArgumentParser()
parser.add_argument("--from-version", help="From version to document", type=str, required=True)
parser.add_argument("--to-version", help="To version to document", type=str, required=True)
parser.add_argument("--documentation-dir", help="deployment yaml file to update", type=str,
                    default=os.path.join(os.path.dirname(__file__), "../versions_documentation"))
parser.add_argument("--repo", help="repo to document", type=str, default="assisted-service")
args = parser.parse_args()

documentation_path = os.path.join(args.documentation_dir, args.repo)


def main():
    version_documentation_list = list()

    if not os.path.exists(documentation_path):
        os.makedirs(documentation_path)

    os.mkdir("temp")
    try:
        git_logs_line = get_versions_log()
        process_logs(git_logs_line, version_documentation_list)
        write_documentation_to_file(version_documentation_list)
    except Exception as ex:
        logging.error('Failed to process versions documentation: {}'.format(ex))
    finally:
        shutil.rmtree("temp")


def process_logs(git_logs_line, version_documentation_list):
    for line in git_logs_line:
        line = line.strip().decode("utf-8")
        if is_line_metadata(line):
            continue
        line = line.strip('* ')

        if re.match(valid_commit_regex, line):
            version_documentation_list.append(line)


def get_versions_log():
    repo_url = REPO_URL_TEMPLATE.format(args.repo)
    subprocess.check_output("git clone {}".format(repo_url), shell=True, cwd="temp")
    raw_log = subprocess.check_output("git log {tagS}...{tagE} ".format(tagS=args.from_version, tagE=args.to_version),
                                      shell=True, cwd="temp/assisted-service")
    print("*"*0)
    git_logs_line = raw_log.splitlines()
    return git_logs_line


def write_documentation_to_file(version_documentation_list):
    version_documentation = '\n'.join(version_documentation_list)
    file_name = "version_documentation_{}_to_{}".format(args.from_version, args.to_version)
    file_path = os.path.join(documentation_path, file_name)

    logging.info("Writing version documentation to {}".format(file_path))
    logging.info("Version documentation: {}".format(version_documentation))
    with open(file_path, 'w') as f:
        f.write(version_documentation)


def is_line_metadata(line):
    line_starts_with = ['commit', 'Author', 'Date:']
    for meta_prefix in line_starts_with:
        if line.startswith(meta_prefix):
            return True
    if line == '':
        return True


if __name__ == "__main__":
    main()
