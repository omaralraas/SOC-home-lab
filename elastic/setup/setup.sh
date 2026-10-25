#!/usr/bin/env bash
# One-shot bootstrap for the Elastic tier (run by the `setup` compose service).
#  - sets the kibana_system password so Kibana can connect
#  - attaches a 30-day retention lifecycle policy to the logs-soc.* data streams
#  - creates a role that may only write the logs-soc.* data streams, and the
#    logstash_internal user Logstash authenticates as
set -euo pipefail

ES=http://elasticsearch:9200
auth=(-s -f -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json")

for var in ELASTIC_PASSWORD KIBANA_PASSWORD LOGSTASH_PASSWORD; do
  [[ -n "${!var:-}" ]] || { echo "$var is not set" >&2; exit 1; }
done

echo "Setting kibana_system password"
curl "${auth[@]}" -X POST "$ES/_security/user/kibana_system/_password" \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}" >/dev/null

echo "Creating soc-logs lifecycle policy (roll over weekly or at 10 GB, delete after 30 days)"
curl "${auth[@]}" -X PUT "$ES/_ilm/policy/soc-logs" -d '{
  "policy": {
    "phases": {
      "hot": {"actions": {"rollover": {"max_age": "7d", "max_primary_shard_size": "10gb"}}},
      "delete": {"min_age": "30d", "actions": {"delete": {}}}
    }
  }
}' >/dev/null

# The built-in logs-*-* index template composes logs@custom, so every
# logs-soc.* backing index picks up the policy.
curl "${auth[@]}" -X PUT "$ES/_component_template/logs@custom" -d '{
  "template": {"settings": {"index.lifecycle.name": "soc-logs"}}
}' >/dev/null

echo "Creating soc_logstash_writer role"
curl "${auth[@]}" -X PUT "$ES/_security/role/soc_logstash_writer" -d '{
  "cluster": ["monitor"],
  "indices": [{
    "names": ["logs-soc.*-*"],
    "privileges": ["create_doc", "auto_configure", "view_index_metadata"]
  }]
}' >/dev/null

echo "Creating logstash_internal user"
curl "${auth[@]}" -X PUT "$ES/_security/user/logstash_internal" \
  -d "{\"password\":\"${LOGSTASH_PASSWORD}\",\"roles\":[\"soc_logstash_writer\"],\"full_name\":\"Logstash writer\"}" >/dev/null

echo "Setup complete"
