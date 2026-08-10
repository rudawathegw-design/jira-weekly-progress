"""
fetch_jira.py
Fetches all issues for a project from Jira Cloud.
Credentials via GitHub Secrets / env vars:
    JIRA_EMAIL, JIRA_API_TOKEN, JIRA_BASE_URL, JIRA_PROJECT
"""

import os
import sys
import base64
import requests


def get_headers(email, token):
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {"Accept": "application/json", "Authorization": f"Basic {auth}"}


def fetch_all_issues(base_url, email, token, jql):
    headers  = get_headers(email, token)
    base_url = base_url.rstrip("/")
    url      = f"{base_url}/rest/api/3/search/jql"
    all_issues, next_page_token = [], None

    while True:
        params = {
            "jql": jql,
            "maxResults": 100,
            # duedate added for overdue calculation; priority for richer AI analysis
            "fields": "summary,assignee,status,duedate,priority,issuetype,statuscategorychangedate,updated,customfield_10784,customfield_10785,customfield_10092,customfield_10520",
            # expand=changelog returns the last 100 changelog entries per
            # issue (author + field + from/to + timestamp). Powers the
            # 'Activity Log' modal — who changed what, when.
            "expand": "changelog",
        }
        if next_page_token:
            params["nextPageToken"] = next_page_token

        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(f"Jira API error HTTP {resp.status_code}: {resp.text[:300]}")

        data = resp.json()
        all_issues.extend(data.get("issues", []))
        next_page_token = data.get("nextPageToken")
        if not next_page_token or data.get("isLast"):
            break

    return all_issues


def main():
    email    = os.environ.get("JIRA_EMAIL", "")
    token    = os.environ.get("JIRA_API_TOKEN", "")
    base_url = os.environ.get("JIRA_BASE_URL", "https://fibtask.atlassian.net")
    project  = os.environ.get("JIRA_PROJECT", "FIBTMP")

    if not email or not token:
        print("ERROR: JIRA_EMAIL and JIRA_API_TOKEN must be set.", file=sys.stderr)
        sys.exit(1)

    jql = f"project = {project} ORDER BY created DESC"
    print(f"Fetching issues for project {project} …")
    issues = fetch_all_issues(base_url, email, token, jql)
    print(f"Fetched {len(issues)} issues.")
    return issues


if __name__ == "__main__":
    main()
