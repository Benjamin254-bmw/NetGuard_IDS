# ADR 0004: Synchronous SQLAlchemy 2 with psycopg 3
Status: accepted. Small-network workload; FastAPI runs sync endpoints in a thread pool and the
monitor uses threads with bounded queues. Avoids async complexity. Revisit only if measurement
shows the API is a bottleneck.
