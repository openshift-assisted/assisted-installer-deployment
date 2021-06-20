# Triage Signatures
Signatures are modules that perform automatic processing and analysis of triage logs to generate useful snippets of information to aid the user triaging the cluster failure.

If you're looking to add new triage signatures to help the triaging efforts, you can do so by implementing them as subclasses of the `Signature` class inside the `./tools/add_triage_signature.py` script. Don't forget to also add the new signature class type to the `SIGNATURES` global list.

You can look at how other signatures perform various operations to take inspiration on how to write your own signature.

In order to test your new signatures, you can run the script locally to make sure your new signatures work correctly. This can be done using the “Dry Run” mode of the signature script -

1. Create a `~/.netrc` file with your JIRA credentials, for example:
```
    machine issues.redhat.com
    login yourjirausernamehere
    password yourpasswordhere
```
(Your username can be found in https://issues.redhat.com/secure/ViewProfile.jspa)

2. Connect to the Red Hat VPN

3. If you haven't already, create a new Python virtualenv (`virtualenv venv`)

4. Activate the virtualenv `. ./venv/bin/activate`

5. Install `requirements.txt` (`python3 -m pip install -r requirements.txt`)
(On Fedora, this step may need the `python3-devel` package to be installed first)

6. Run `./tools/add_triage_signature.py`, using flags `--dry-run` or `--dry-run-temp`, along with `--issue MGMT-1234` or `--recent-issues`

7. Inspect the output to make sure everything is in order. Optionally, you can copy the generated output and paste it inside a JIRA comment textbox (make sure it's set to "Text" mode), then change the textbox to "Visual" mode to view the formatted output.


