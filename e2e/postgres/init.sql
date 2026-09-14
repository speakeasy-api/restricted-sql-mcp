CREATE EXTENSION IF NOT EXISTS hypopg;

CREATE TABLE allowed_customers (
    id    integer PRIMARY KEY,
    name  text NOT NULL,
    email text NOT NULL
);

CREATE TABLE allowed_orders (
    id          integer PRIMARY KEY,
    customer_id integer NOT NULL REFERENCES allowed_customers (id),
    amount      numeric(10, 2) NOT NULL,
    status      text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX allowed_orders_customer_idx ON allowed_orders (customer_id);
COMMENT ON TABLE allowed_orders IS 'Orders';

CREATE TABLE allowed_audit (
    id         serial PRIMARY KEY,
    note       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE forbidden_secrets (
    id     integer PRIMARY KEY,
    secret text NOT NULL
);

CREATE VIEW allowed_orders_v AS SELECT id, amount FROM allowed_orders;
CREATE SEQUENCE allowed_seq;

INSERT INTO allowed_customers (id, name, email) VALUES
    (1, 'Ada',   'ada@example.com'),
    (2, 'Grace', 'grace@example.com'),
    (3, 'Linus', 'linus@example.com');

INSERT INTO allowed_orders (id, customer_id, amount, status, created_at) VALUES
    (1, 1, 10.00,  'paid',      '2026-01-01T10:00:00Z'),
    (2, 1, 25.50,  'paid',      '2026-01-02T10:00:00Z'),
    (3, 2, 7.25,   'pending',   '2026-01-03T10:00:00Z'),
    (4, 3, 100.00, 'cancelled', '2026-01-04T10:00:00Z'),
    (5, 3, 42.00,  'paid',      '2026-01-05T10:00:00Z');

INSERT INTO forbidden_secrets (id, secret) VALUES (1, 'hunter2');
