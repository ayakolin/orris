-- +goose Up
ALTER TABLE forward_rules ADD COLUMN listen_ip VARCHAR(45) NOT NULL DEFAULT '' AFTER listen_port;

DROP INDEX idx_listen_port_agent_server ON forward_rules;
CREATE UNIQUE INDEX idx_listen_port_agent_server ON forward_rules(agent_id, listen_port, listen_ip, server_address);

-- +goose Down
DROP INDEX idx_listen_port_agent_server ON forward_rules;
CREATE UNIQUE INDEX idx_listen_port_agent_server ON forward_rules(agent_id, listen_port, server_address);

ALTER TABLE forward_rules DROP COLUMN listen_ip;
