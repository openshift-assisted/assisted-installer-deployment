# Triage Signatures
Signatures are modules that perform automatic processing and analysis of triage logs to generate useful snippets of information to aid the user triaging the cluster failure.

If you're looking to add new triage signatures to help the triaging efforts, you can do so by implementing them as subclasses of the `Signature` class inside the `./tools/add_triage_signature.py` script. Don't forget to also add the new signature class type to the `ALL_SIGNATURES` global list.

You can look at how other signatures perform various operations to take inspiration on how to write your own signature.

## Signature development

In order to test your new signatures, you can run the script locally to make sure your new signatures work correctly. This can be done using the “Dry Run” mode of the signature script -

1. Generate your Personal Access Token in JIRA by going to https://issues.redhat.com/secure/ViewProfile.jspa?selectedTab=com.atlassian.pats.pats-plugin:jira-user-personal-access-tokens

2. Connect to the Red Hat VPN

3. If you haven't already, create a new Python virtualenv (`virtualenv venv`)

4. Activate the virtualenv `. ./venv/bin/activate`

5. Install `requirements.txt` (`python3 -m pip install -r requirements.txt`)
(On Fedora, this step may need the `python3-devel` package to be installed first)

6. Run `export JIRA_ACCESS_TOKEN=<my-secret-token>`

7. Run `./tools/add_triage_signature.py`, using flags `--dry-run` or `--dry-run-temp`, along with `--issue AITRIAGE-3400` or `--recent-issues`

Examples:

- Test all signatures against AITRIAGE-3400 `./tools/add_triage_signature.py --dry-run --issue AITRIAGE-3400`
- Test all signatures against AITRIAGE-3400 and write output to files in /tmp/ `./tools/add_triage_signature.py --dry-run-temp --issue AITRIAGE-3400`
- Test all signatures against all recent issues `./tools/add_triage_signature.py --dry-run --recent-issues`

8. Inspect the output to make sure everything is in order. Optionally, you can copy the generated output and paste it inside a JIRA comment textbox (make sure it's set to "Text" mode), then change the textbox to "Visual" mode to view the formatted output.


