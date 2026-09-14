CREATE DATABASE IF NOT EXISTS app;

CREATE TABLE app.allowed_customers (
    id    Int32,
    name  String,
    email String
) ENGINE = MergeTree ORDER BY id;

CREATE TABLE app.allowed_orders (
    id          Int32,
    customer_id Int32,
    amount      Decimal(10, 2),
    status      String,
    created_at  DateTime
) ENGINE = MergeTree ORDER BY id;

CREATE TABLE app.allowed_audit (
    id         Int32,
    note       String,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree ORDER BY id;

CREATE TABLE app.forbidden_secrets (
    id     Int32,
    secret String
) ENGINE = MergeTree ORDER BY id;

CREATE VIEW app.allowed_orders_v AS SELECT id, amount FROM app.allowed_orders;

INSERT INTO app.allowed_customers (id, name, email) VALUES
    (1, 'Ada',   'ada@example.com'),
    (2, 'Grace', 'grace@example.com'),
    (3, 'Linus', 'linus@example.com');

INSERT INTO app.allowed_orders (id, customer_id, amount, status, created_at) VALUES
    (1, 1, 10.00,  'paid',      '2026-01-01 10:00:00'),
    (2, 1, 25.50,  'paid',      '2026-01-02 10:00:00'),
    (3, 2, 7.25,   'pending',   '2026-01-03 10:00:00'),
    (4, 3, 100.00, 'cancelled', '2026-01-04 10:00:00'),
    (5, 3, 42.00,  'paid',      '2026-01-05 10:00:00');

INSERT INTO app.forbidden_secrets (id, secret) VALUES (1, 'hunter2');
