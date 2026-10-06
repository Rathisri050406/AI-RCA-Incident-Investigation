# Database Timeout and Application Failure Troubleshooting (project notes)
Repeated database timeouts with application errors such as connection pool exhaustion typically point to database performance problems: slow or blocking queries, lock contention, missing indexes, insufficient connections or resource saturation.
Check: slow query logs, active locks, connection counts against the pool size, CPU, memory and disk I/O on the database host, and recent deployments or schema changes.
Application errors without database timeouts suggest a code defect or dependency failure instead. Compare timelines of the database and application logs to see which failure came first.
Handling: stabilise first (restart or scale only with approval), then fix the root cause such as query optimisation or pool sizing.
