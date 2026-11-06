#!/usr/bin/env python3
"""Stage, verify, and publish the signed Kotlin bundle in Maven Central."""

import argparse
import base64
import json
import os
import pathlib
import time
import urllib.error
import urllib.request
import zipfile

BASE = "https://central.sonatype.com/api/v1/publisher"


def request(path, data=None, content_type=None):
    user = os.environ["CENTRAL_PORTAL_USERNAME"]
    password = os.environ["CENTRAL_PORTAL_PASSWORD"]
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": f"Bearer {token}"}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        raise SystemExit(f"Central Portal {path}: HTTP {error.code}: {error.read().decode()[:500]}") from error


def wait_for(deployment, desired):
    for _ in range(60):
        status = json.loads(request(f"/status?id={deployment}", b""))
        state = status.get("deploymentState")
        print(f"Central deployment {deployment}: {state}", flush=True)
        if state == desired:
            return
        if state in ("FAILED", "PUBLISHING_FAILED"):
            raise SystemExit(f"Central deployment failed: {status}")
        time.sleep(15)
    raise SystemExit(f"Central deployment did not reach {desired}")


parser = argparse.ArgumentParser()
parser.add_argument("action", choices=("stage", "publish"))
parser.add_argument("--bundle", type=pathlib.Path)
parser.add_argument("--deployment")
args = parser.parse_args()
if args.action == "stage":
    if not args.bundle:
        parser.error("stage requires --bundle")
    boundary = "ratify-mobile-central"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"bundle\"; filename=\"bundle.zip\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + args.bundle.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    deployment = request("/upload?publishingType=USER_MANAGED", body, f"multipart/form-data; boundary={boundary}").decode().strip()
    if not deployment:
        raise SystemExit("Central Portal returned no deployment ID")
    wait_for(deployment, "VALIDATED")
    with zipfile.ZipFile(args.bundle) as bundle:
        for name in bundle.namelist():
            if name.endswith((".aar", ".pom")):
                remote = request(f"/deployment/{deployment}/download/{name}")
                if remote != bundle.read(name):
                    raise SystemExit(f"Central staged bytes differ: {name}")
    print(f"DEPLOYMENT_ID={deployment}")
else:
    if not args.deployment:
        parser.error("publish requires --deployment")
    request(f"/deployment/{args.deployment}", b"")
    wait_for(args.deployment, "PUBLISHED")
