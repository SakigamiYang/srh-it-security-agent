#!/bin/bash

mongosh \
  --username "$MONGO_INITDB_ROOT_USERNAME" \
  --password "$MONGO_INITDB_ROOT_PASSWORD" \
  --authenticationDatabase admin <<EOF

use ${MONGO_INITDB_DATABASE}

db.createUser({
    user: "${MONGO_APP_USERNAME}",
    pwd: "${MONGO_APP_PASSWORD}",
    roles: [
        {
            role: "readWrite",
            db: "${MONGO_INITDB_DATABASE}"
        }
    ]
})
EOF