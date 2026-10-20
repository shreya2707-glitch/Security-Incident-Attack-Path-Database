# Security Incident Attack-Path Database

A MySQL-based DBMS academic project for organizing illustrative cybersecurity incident records and reconstructing ordered attack paths.

## Project overview

The schema connects incidents, actors, assets, MITRE ATT&CK groups/techniques/software, ordered attack events, evidence, and incident-response activities. `ATTACK_EVENT` is the central relationship table; `Event_Order` records the sequence of steps within an incident.

**Data note:** the report states that the project's records are illustrative sample data, not real incidents.

## Repository structure

```text
SecurityAttackPathDB/
├── sql/
│   └── project_queries.sql
├── dashboard/
│   └── index.html
├── docs/
│   └── DBMS_Project_Report_Members_1-4.docx
├── README.md
└── .gitignore
```

## Requirements

- MySQL 8.x recommended
- MySQL Workbench or MySQL command-line client
- A browser for the static dashboard prototype

## Running the SQL

1. Open MySQL Workbench and connect to your local MySQL server.
2. Select the database used by your team (the report calls it `SecurityAttackPathDB` / `securityattackpathdb`).
3. Run the team's original schema and sample-data setup first, respecting foreign-key dependencies.
4. Open `sql/project_queries.sql` and run only the required query or section at a time.
5. Stored functions, procedures, and triggers use MySQL `DELIMITER` syntax. Run each routine definition as a complete block.
6. Some examples intentionally test invalid input or demonstrate transactions/row locks. Do not run those blindly against important data.

## SQL topics demonstrated

- `SELECT`, `WHERE`, `LIKE`, `IN`, `IS NULL`, `DISTINCT`, `ORDER BY`
- `INNER JOIN`, `LEFT JOIN`, multi-table joins
- Aggregate functions, `GROUP BY`, `HAVING`
- Nested queries and `CASE`
- Views
- Stored functions and procedures
- Triggers and audit logging
- Transactions, savepoints, rollback/commit, row locking
- Functional dependencies, normalization, and serializability are documented in the project report

## Dashboard note

The browser dashboard is a static prototype and uses illustrative sample data. It is not connected to MySQL unless a backend integration is implemented separately. Never put database credentials in browser-side JavaScript.

## Suggested Git commands

```bash
git init
git add .
git commit -m "Add Security Incident Attack-Path DBMS project"
git branch -M main
git remote add origin [https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git](https://github.com/shreya2707-glitch/Security-Incident-Attack-Path-Database/)
git push -u origin main
```


