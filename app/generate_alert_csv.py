"""
Emailing Prisma Rule CSVs Script

This file performs the emailing of alerts based on alert rules, which includes:
    # - RQL query through Prisma
    # - Parse the RQL for a unique tag
    - Get existing alert rules in Prisma
    - Parse the alert rules prepended with
        the automation prefix indicating automated alert rules only
    - Grab alerts for each Alert Rule with the APM_ID tag
    - Generate the CSV for each Alert Rule
    - Email the CSV to the APM_ID tag

Usage:
    python email_rule_csvs.py

Options:

Requirements:
    - Python 3.10 or higher
    - .env configured with the following variables,
        - PRISMA_ACCESS_KEY
        - PRISMA_SECRET_KEY

Example:
    python email_rule_csvs.py

Note:
    This script is meant to be deployed in Azure Function.
"""

import os
import json
from helpers import generate_prisma_token
from helpers import prisma_rql_query
from helpers import prisma_get_alert_rules
from helpers import prisma_get_alerts
from helpers import write_data_to_csv
from helpers import logger


def main(data="", context=""):
    """
    Export alerts to CSV.

    Parameters:
        data: required for Azure function deployment
        context: required for Azure function deployment

    Returns:
        None
    """

    ###########################################################################
    # local variables
    prisma_access_key = os.getenv("ACCESS_KEY")
    prisma_secret_key = os.getenv("SECRET_KEY")
    rql_query = os.getenv("RQL_QUERY")
    rql_time_range = json.loads(os.getenv("RQL_TIME_RANGE"))
    unique_tag = os.getenv("UNIQUE_ATTRIBUTE")
    automation_prefix = os.getenv("AUTOMATION_PREFIX")

    try:
        rql_limit = int(os.getenv("RQL_LIMIT"))
    except ValueError:
        rql_limit = None

    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    ###########################################################################
    # RQL query through Prisma.

    # prisma_query_response = prisma_rql_query(
    #     prisma_token, rql_query, time_range=rql_time_range, limit=rql_limit
    # )

    ##########################################################################
    # Parse the RQL for a unique tag

    # logger.info("Parsing RQL query response for %s in the tags", unique_tag)

    # tag_list = list()

    # if prisma_query_response:
    #     for item in prisma_query_response:
    #         if "tags" in item["data"]:
    #             if unique_tag in item["data"]["tags"]:
    #                 tag_list.append(item["data"]["tags"][unique_tag])

    # else:
    #     logger.info("The query,\n\t%s\ndid not return anything.", rql_query)

    # unique_tags = list(set(tag_list))

    # logger.info("Found %i unique tags that match %s", len(unique_tags), unique_tag)

    ###########################################################################
    #   Get existing alert rules in Prisma

    alert_rules, status_code = prisma_get_alert_rules(prisma_token)

    ###########################################################################
    #   Parse the alert rules prepended with
    #       the automation prefix indicating automated alert rules only.

    logger.info("Parsing alert rules prefixed with %s", automation_prefix)

    auto_generated_alert_rules = list()

    if status_code == 200:
        for alert_rule in alert_rules:
            if str(alert_rule["name"]).startswith(automation_prefix):
                keys = [k for k in alert_rule["target"]["tags"]]
                tags = {key["key"]: key["values"] for key in keys}
                if unique_tag in tags:
                    # the unique_tag is found in the alert rule
                    auto_generated_alert_rules.append(alert_rule)

    ###########################################################################
    # Grab alerts for each Alert Rule with the APM_ID tag

    page_limit = 1000
    next_page = ""

    for alert_rule in auto_generated_alert_rules:
        keys = [k for k in alert_rule["target"]["tags"]]
        tags = {key["key"]: key["values"] for key in keys}
        email_recipient = tags[unique_tag][0]

        while True:
            alert_rule_name = alert_rule["name"]
            csv_name = f"{automation_prefix}-{email_recipient}-{alert_rule_name}.csv"

            alerts_response, status_code = prisma_get_alerts(
                prisma_token,
                alert_rule_name,
                page_token=next_page,
                page_limit=page_limit,
                detailed=True,
            )

            if status_code == 200:
                if alerts_response["items"] is not None:
                    write_data_to_csv(csv_name, alerts_response["items"])

                if "nextPageToken" in alerts_response:
                    next_page = alerts_response["nextPageToken"]
                else:
                    next_page = ""
                    break
            elif status_code == 401:
                logger.error(
                    "Prisma token timed out," "generating a new one and continuing."
                )

                prisma_token = generate_prisma_token(
                    prisma_access_key, prisma_secret_key
                )


if __name__ == "__main__":
    main()
