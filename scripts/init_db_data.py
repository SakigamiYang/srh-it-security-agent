from pathlib import Path

from dotenv import dotenv_values
from loguru import logger
from pymongo import MongoClient, InsertOne

from load_nvd_json import load_nvd_json

ENV_PATH = Path(__file__).parents[1] / ".env"
NVDCVE_PATH = Path(__file__).parents[1] / "data" / "nvdcve"

env = dotenv_values(ENV_PATH)

username = env["MONGO_INITDB_ROOT_USERNAME"]
password = env["MONGO_INITDB_ROOT_PASSWORD"]
port = env.get("MONGO_PORT", "27017")

client = MongoClient(f"mongodb://{username}:{password}@localhost:{port}/admin")
db = client.it_security_agent
collection = db.cves


def write_db(path: Path):
    operations = []

    for doc in load_nvd_json(path):

        operations.append(
            InsertOne(doc)
        )

        if len(operations) == 1000:
            collection.bulk_write(operations, ordered=False)
            operations.clear()

    if operations:
        collection.bulk_write(operations, ordered=False)


collection.delete_many({})

for json_file in sorted(NVDCVE_PATH.glob("nvdcve-2.0-*.json")):
    logger.info(f"Processing {json_file.name}")
    write_db(json_file)

collection.create_index("year")
collection.create_index("published")
collection.create_index("last_modified")

collection.create_index("vendors")
collection.create_index("products")
collection.create_index("cpes")
collection.create_index("cwes")

collection.create_index("searchable")

collection.create_index("cvss.score")
collection.create_index("cvss.severity")
collection.create_index("status")
