# Security Incident Attack-Path Database

A MySQL-based Database Management System (DBMS) academic project for organizing cybersecurity incident records, mapping attack techniques, and reconstructing ordered attack paths.

## 📌 Project Overview

Cybersecurity incidents can involve multiple attackers, systems, techniques, and software tools. Understanding the sequence of events helps security teams analyze incidents and plan appropriate responses.

The **Security Incident Attack-Path Database** is designed to store and organize this information in a structured relational database. It demonstrates how DBMS concepts and SQL queries can be applied to cybersecurity incident analysis.

## 🎯 Objectives

- Design a relational database for cybersecurity incident records.
- Store information about threat actors, affected assets, techniques, and software.
- Represent the sequence of events involved in an attack path.
- Connect incidents with evidence sources and response activities.
- Apply SQL concepts including joins, subqueries, aggregate functions, views, functions, procedures, and triggers.
- Demonstrate database normalization, relationships, and transaction concepts.

## 🛠️ Technology Stack

- **Database:** MySQL
- **Query Language:** SQL
- **Documentation:** PDF
- **Version Control:** Git and GitHub

## 📂 Repository Contents

| File | Description |
|---|---|
| `Security Incident Attack-Path.pdf` | Project report containing the project documentation and DBMS concepts. |
| `data.sql` | SQL script for database initialization, table creation, and sample data, as defined in the script. |
| `query.sql` | Collection of SQL queries for database operations and analysis. |
| `README.md` | Project overview and instructions. |

## 🗃️ Database Design

The database is organized around nine core tables:

| Table | Purpose |
|---|---|
| `MITRE_GROUP` | Stores information about threat groups. |
| `MITRE_TECHNIQUE` | Stores attack techniques. |
| `MITRE_SOFTWARE` | Stores software associated with attack activity. |
| `SECURITY_INCIDENT` | Stores cybersecurity incident records. |
| `ACTOR` | Stores information about actors involved in incidents. |
| `ASSET` | Stores information about affected systems or assets. |
| `ATTACK_EVENT` | Connects incident details and represents the ordered events in an attack path. |
| `EVIDENCE_SOURCE` | Stores references to evidence associated with incidents. |
| `INCIDENT_RESPONSE` | Stores incident response information and status. |

`ATTACK_EVENT` is a central table because it connects an incident with related actors, assets, techniques, and, where applicable, software. The event-order field helps represent the sequence of attack activity.

*Note: The table descriptions above summarize the intended design. Refer to `data.sql` for the actual schema and column definitions.*

## ⚙️ Getting Started

### Prerequisites

- MySQL Server installed and running.
- MySQL Workbench or the MySQL command-line client.
- Git, if you want to clone the repository.

### 1. Clone the repository

```bash
git clone https://github.com/shreya2707-glitch/Security-Incident-Attack-Path-Database.git
```

### 2. Open the project folder

```bash
cd Security-Incident-Attack-Path-Database
```

### 3. Initialize the database

Open `data.sql` in MySQL Workbench and review the script. Execute it to create the database, tables, and any sample records included in the file.

Alternatively, from the MySQL command-line client, run:

```sql
SOURCE /full/path/to/data.sql;
```

Replace `/full/path/to/data.sql` with the actual path to the downloaded file. On Windows, use the appropriate path for your computer.

### 4. Verify the database

If the database is named `SecurityAttackPathDB`, select it and check the available tables:

```sql
USE SecurityAttackPathDB;

SHOW TABLES;
```

If your script uses a different database name, use the name defined in `data.sql`.

### 5. Run the SQL queries

Open `query.sql` in MySQL Workbench or another MySQL client. Execute the queries individually or by section after confirming that the required tables and columns exist.

**Important:** Some queries may depend on particular tables, sample records, or database objects being created first. Review each section before executing it.

## 🔍 SQL Concepts Demonstrated

The project is intended to demonstrate the following DBMS concepts, where implemented in the SQL scripts:

- **DDL:** `CREATE`, `ALTER`, and other schema-definition operations.
- **DML:** `INSERT`, `UPDATE`, and `DELETE`.
- **Filtering:** `WHERE`, comparison operators, and logical operators.
- **Joins:** Combining related information from multiple tables.
- **Nested queries:** Using subqueries to retrieve related data.
- **Aggregate functions:** `COUNT()`, `SUM()`, `AVG()`, `MIN()`, and `MAX()`.
- **Grouping:** `GROUP BY` and `HAVING`.
- **Views:** Presenting reusable query results.
- **Stored functions and procedures:** Encapsulating database operations.
- **Triggers:** Automating database actions in response to specified events.
- **Normalization:** Organizing relational data to reduce redundancy and anomalies.
- **Transactions and serializability:** Studying the correctness of concurrent database operations.

The exact concepts available in the submitted implementation can be verified in `query.sql` and `data.sql`.

## 📊 Expected Use Cases

The database design supports analysis such as:

- Retrieving incidents and their associated attack events.
- Examining attack-event sequences for a selected incident.
- Finding techniques associated with recorded incidents.
- Identifying assets linked to attack activity.
- Reviewing evidence associated with incidents.
- Checking incident response records and their statuses.
- Summarizing incident data using aggregate queries.

These are database analysis use cases; the results depend on the records present in the database.

## 🧪 Testing and Demonstration

For a project demonstration:

1. Execute `data.sql`.
2. Verify that the expected tables and sample records exist.
3. Run selected queries from `query.sql`.
4. Demonstrate joins, grouping, nested queries, and other implemented SQL concepts.
5. Show the results in MySQL Workbench or your MySQL client.
6. Explain the relationships between the tables and how `ATTACK_EVENT` represents the attack sequence.

## ⚠️ Scope and Limitations

- This is an academic DBMS project, not a production cybersecurity monitoring system.
- Sample data should be treated as illustrative unless individual records have been independently verified.
- The database analyzes stored records; it does not automatically detect live cyberattacks.
- The project does not establish that an attack occurred in real time.
- Any dashboard or visualization must be connected to a backend and database to provide live database results.

## 🚀 Future Enhancements

- Develop a web dashboard connected to the MySQL database.
- Add interactive attack-path visualization.
- Integrate verified threat intelligence and MITRE ATT&CK references.
- Add authentication and role-based access control.
- Improve evidence tracking and incident response reporting.
- Add validation, automated testing, and more realistic sample datasets.

## 🎓 Academic Project

**Project:** Security Incident Attack-Path Database  
**Subject:** Database Management Systems (DBMS)  
**Institution:** Symbiosis Institute of Technology,Pune 
**Academic Year:** 2026–2027

## 👥 Contributors

This project was developed as a collaborative academic project. 
Saurav Paudel - 25070122174
Shreeya Alwar - 25070122180
Shreya Panda - 25070122181
Sneha Sah- 25070122189

## 📄 License

This repository is intended for academic and educational use. No open-source license has been specified. Please contact the repository owner for permission before reusing or redistributing the project.
