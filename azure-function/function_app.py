import os
import csv
import json
import logging
from io import StringIO
import azure.functions as func
from azure.core import exceptions
from azure.storage.blob import BlobServiceClient
from helpers import generate_prisma_token
from helpers import prisma_rql_query
from helpers import prisma_get_alert_rules
from helpers import prisma_get_alerts

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)


app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

CRON_SCHEDULE = os.getenv("CRON_SCHEDULE")


@app.function_name(name="alert_rule_csv_automation_timer_trigger")
@app.schedule(
    schedule=CRON_SCHEDULE, arg_name="timer", run_on_startup=False, use_monitor=True
)
def alert_rule_csv_automation_timer(timer: func.TimerRequest):
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
    prisma_access_key = os.getenv("PRISMA_ACCESS_KEY")
    prisma_secret_key = os.getenv("PRISMA_SECRET_KEY")
    # rql_query = os.getenv("RQL_QUERY")
    # rql_time_range = json.loads(os.getenv("RQL_TIME_RANGE"))
    blob_store_connection_string = os.getenv("AzureWebJobsStorage")
    unique_tag = os.getenv("UNIQUE_ATTRIBUTE")
    automation_prefix = os.getenv("AUTOMATION_PREFIX")

    # try:
    #     rql_limit = int(os.getenv("RQL_LIMIT"))
    # except ValueError:
    #     rql_limit = None

    csv_fields = json.loads(os.getenv("CSV_COLUMNS"))
    csv_fields_of_interest = json.loads(os.getenv("CSV_FIELDS_OF_INTEREST"))

    prisma_token = generate_prisma_token(prisma_access_key, prisma_secret_key)

    ###########################################################################
    # Initialize blob store client

    blob_service_client = BlobServiceClient.from_connection_string(
        blob_store_connection_string
    )

    container_name = "prisma-alert-reports"
    container_client = blob_service_client.get_container_client(container_name)

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
            blob_name = f"{automation_prefix}-{email_recipient}-{alert_rule_name}.csv"
            blob_client = container_client.get_blob_client(blob_name)

            ###################################################################
            # Delete the CSV file if it exists from a previous run
            try:
                container_client.delete_blob(blob_name)
            except exceptions.ResourceNotFoundError:
                pass

            alerts_response, status_code = prisma_get_alerts(
                prisma_token,
                alert_rule_name,
                page_token=next_page,
                page_limit=page_limit,
                detailed=True,
            )

            if status_code == 200:
                if alerts_response["items"] is not None:
                    alerts_list = list()
                    incremental_id = 0

                    for alert in alerts_response["items"]:
                        alert_dict = {"Incremental_ID": incremental_id}

                        # Grab base alert information
                        if csv_fields_of_interest:
                            alert_dict.update(
                                {
                                    key: value
                                    for key, value in alert.items()
                                    if (key in csv_fields_of_interest)
                                }
                            )
                        else:
                            alert_dict.update(
                                {key: value for key, value in alert.items()}
                            )

                        alerts_list.append(alert_dict)

                        incremental_id += 1

                    ###########################################################
                    # Write to CSV
                    if alerts_list:
                        write_csv_to_blob(
                            blob_name,
                            alerts_list,
                            csv_fields,
                            blob_client,
                            new_file=True,
                        )

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


def write_csv_to_blob(
    file_path: str,
    data_list: list[dict],
    field_names: list[str],
    blob_client,
    new_file=False,
) -> None:
    """
    Writes list of iterable data to CSV.

    Parameters:
    file_path (str): File path
    data_list (list[dict]): List of dictionaries

    """
    logger.info("Writing data to %s", file_path)

    csv_buffer = StringIO()

    writer = csv.DictWriter(csv_buffer, fieldnames=field_names)

    if new_file:
        writer.writeheader()

    # Write the CSV rows
    try:
        for data in data_list:
            writer.writerow(data)
    except ValueError as ex:
        logger.error(
            "%s\r\nPlease add it CSV_COLUMNS environment variable list.", str(ex)
        )

        raise

    # Upload the CSV data to the blob
    blob_client.upload_blob(csv_buffer.getvalue().encode("utf-8"), overwrite=True)
