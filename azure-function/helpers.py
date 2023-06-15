"""
This file contains a collection of helper functions for automating tasks.

Functions:
- generate_prisma_token(access_key, secret_key): Returns a PRISMA token.
- prisma_rql_query(token, query, time_range, limit): Returns query response

Usage:
Simply import this file and call the function. For example:

    from helpers import generate_prisma_token
    prisma_token = generate_prisma_token()

Note:
Before using these functions, be sure to configure the .env appropriately.
"""

import os
import json
import logging
import requests
from dotenv import load_dotenv


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

load_dotenv()

CSPM_ENDPOINT = os.getenv("CSPM_API")
CWPP_ENDPOINT = os.getenv("CWPP_API")


def generate_prisma_token(access_key: str, secret_key: str) -> str:
    """
    Generate the token for Prisma API access.

    https://pan.dev/prisma-cloud/api/cspm/app-login/

    Parameters:
    access_key (str): Prisma generated access key
    secret_key (str): Prisma generated secret key

    Returns:
    str: Prisma token

    """
    endpoint = f"https://{CSPM_ENDPOINT}/login"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }

    body = {"username": access_key, "password": secret_key}

    logger.info("Generating Prisma token using endpoint: %s", endpoint)

    response = requests.post(endpoint, headers=headers, json=body, timeout=360)

    data = json.loads(response.text)

    return data["token"]


def prisma_rql_query(token: str, query: str, time_range="", limit="") -> list:
    """
    Queries GCP using Prisma as the middleman.

    https://pan.dev/prisma-cloud/api/cspm/search-config/

    Parameters:
    token (str): Prisma token for API access.
    query (str): RQL query.
    time_range(str): optional, limit items returned based on time range.
    limit (int): optional, limit items returned in the RQL query.

    Returns:
    list: Query response.

    """
    endpoint = f"https://{CSPM_ENDPOINT}/search/config"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    payload = {
        "query": query,
    }

    if time_range:
        payload.update({"timeRange": time_range})

    if limit:
        payload.update({"limit": int(limit)})

    logger.info("Sending the following query to Prisma,\n\t%s", payload)

    response = requests.post(endpoint, json=payload, headers=headers, timeout=360)

    data = json.loads(response.text)

    return data["data"]["items"]


def prisma_get_alert_rules(token: str):
    """
    Returns all alert rules you have permission to see based on your role.
    The data returned does not include an open alerts count.

    https://pan.dev/prisma-cloud/api/cspm/get-alert-rules-v-2/

    Parameters:
    token (str): Prisma token for API access.

    Returns:
    list[dict]: List of alert rules.

    """
    endpoint = f"https://{CSPM_ENDPOINT}/v2/alert/rule"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    logger.info("Getting Alert Rules from Prisma")

    response = requests.get(endpoint, headers=headers, timeout=360)

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    elif response.status_code == 401:
        return None, 401
    else:
        return None, response.status_code


def prisma_get_alerts(
    token: str, alert_name: str, page_token="", page_limit=1, detailed=True
):
    endpoint = f"https://{CSPM_ENDPOINT}/v2/alert"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": token,
    }

    payload = {
        "detailed": detailed,
        "limit": page_limit,
        "filters": [
            {"name": "timeRange.type", "operator": "=", "value": "ALERT_OPENED"},
            {"name": "alert.status", "operator": "=", "value": "open"},
            {"name": "alertRule.name", "operator": "=", "value": alert_name},
        ],
        "timeRange": {"type": "relative", "value": {"amount": "24", "unit": "hour"}},
    }

    if page_token:
        logger.info(
            "Getting next page of Alerts from Prisma with Alert Rule Name, %s",
            alert_name,
        )

        logger.info("Using pageToken,\n\t%s", page_token)

        payload.update({"pageToken": page_token})
    else:
        logger.info("Getting Alerts from Prisma with Alert Rule Name, %s", alert_name)

    response = requests.post(endpoint, json=payload, headers=headers, timeout=360)

    if response.status_code == 200:
        data = json.loads(response.text)

        return data, 200
    elif response.status_code == 401:
        return None, 401
