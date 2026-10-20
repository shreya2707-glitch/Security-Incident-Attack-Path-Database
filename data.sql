-- ============================================================
-- SECURITY INCIDENT ATTACK-PATH DATABASE
-- MITRE ATT&CK + VERIS HYBRID DATABASE
-- ============================================================

-- Create Database
CREATE DATABASE IF NOT EXISTS SecurityAttackPathDB;

USE SecurityAttackPathDB;


-- ============================================================
-- 1. DROP EXISTING TABLES
-- ============================================================

DROP TABLE IF EXISTS INCIDENT_RESPONSE;
DROP TABLE IF EXISTS EVIDENCE_SOURCE;
DROP TABLE IF EXISTS ATTACK_EVENT;
DROP TABLE IF EXISTS ACTOR;
DROP TABLE IF EXISTS ASSET;
DROP TABLE IF EXISTS SECURITY_INCIDENT;
DROP TABLE IF EXISTS MITRE_SOFTWARE;
DROP TABLE IF EXISTS MITRE_TECHNIQUE;
DROP TABLE IF EXISTS MITRE_GROUP;


-- ============================================================
-- 2. MITRE_GROUP
-- ============================================================

CREATE TABLE MITRE_GROUP (
    Group_ID VARCHAR(10) PRIMARY KEY,
    Group_Name VARCHAR(100) NOT NULL,
    Associated_Groups VARCHAR(300),
    Description VARCHAR(500)
);

INSERT INTO MITRE_GROUP
(Group_ID, Group_Name, Associated_Groups, Description)
VALUES
('G0006', 'APT1', 'Comment Crew, Comment Group',
 'Chinese cyber espionage group'),

('G0016', 'APT29', 'Cozy Bear, The Dukes',
 'Cyber espionage group'),

('G0022', 'APT3', 'Gothic Panda, UPS Team',
 'Threat group associated with China'),

('G0049', 'OilRig', 'Twisted Kitten, Crambus',
 'Threat group targeting organizations'),

('G0102', 'Wizard Spider', 'Grim Spider',
 'Cybercrime threat group');


-- ============================================================
-- 3. MITRE_TECHNIQUE
-- ============================================================

CREATE TABLE MITRE_TECHNIQUE (
    Technique_ID VARCHAR(15) PRIMARY KEY,
    Technique_Name VARCHAR(150) NOT NULL,
    Tactic VARCHAR(100),
    Platform VARCHAR(200)
);

INSERT INTO MITRE_TECHNIQUE
(Technique_ID, Technique_Name, Tactic, Platform)
VALUES

('T1566',
 'Phishing',
 'Initial Access',
 'Enterprise'),

('T1566.002',
 'Phishing: Spearphishing Link',
 'Initial Access',
 'Enterprise'),

('T1204.001',
 'User Execution: Malicious Link',
 'Execution',
 'Enterprise'),

('T1078',
 'Valid Accounts',
 'Defense Evasion',
 'Enterprise'),

('T1059',
 'Command and Scripting Interpreter',
 'Execution',
 'Enterprise'),

('T1059.001',
 'PowerShell',
 'Execution',
 'Windows'),

('T1003',
 'OS Credential Dumping',
 'Credential Access',
 'Windows'),

('T1021',
 'Remote Services',
 'Lateral Movement',
 'Enterprise'),

('T1021.001',
 'Remote Services: RDP',
 'Lateral Movement',
 'Windows'),

('T1087',
 'Account Discovery',
 'Discovery',
 'Enterprise'),

('T1016.001',
 'Internet Connection Discovery',
 'Discovery',
 'Windows'),

('T1027.013',
 'Encrypted/Encoded File',
 'Defense Evasion',
 'Enterprise'),

('T1486',
 'Data Encrypted for Impact',
 'Impact',
 'Enterprise');


-- ============================================================
-- 4. MITRE_SOFTWARE
-- ============================================================

CREATE TABLE MITRE_SOFTWARE (
    Software_ID VARCHAR(10) PRIMARY KEY,
    Software_Name VARCHAR(100) NOT NULL,
    Software_Type VARCHAR(50),
    Platform VARCHAR(100),
    Description VARCHAR(500)
);

INSERT INTO MITRE_SOFTWARE
(Software_ID, Software_Name, Software_Type, Platform, Description)
VALUES

('S0367',
 'Emotet',
 'Malware',
 'Windows',
 'Malware used for initial access'),

('S0363',
 'Empire',
 'Tool',
 'Windows',
 'PowerShell post-exploitation framework'),

('S0260',
 'InvisiMole',
 'Malware',
 'Windows',
 'Modular malware'),

('S0148',
 'RTM',
 'Malware',
 'Windows',
 'Remote access trojan'),

('S0597',
 'GoldFinder',
 'Malware',
 'Windows',
 'Network discovery malware'),

('S0565',
 'Raindrop',
 'Malware',
 'Windows',
 'Loader associated with threat activity'),

('S0575',
 'Conti',
 'Ransomware',
 'Windows',
 'Ransomware malware');


-- ============================================================
-- 5. SECURITY_INCIDENT
-- ============================================================

CREATE TABLE SECURITY_INCIDENT (
    Incident_ID VARCHAR(10) PRIMARY KEY,
    Incident_Year INT,
    Incident_Month INT,
    Security_Incident VARCHAR(30),
    Incident_Type VARCHAR(50),
    Severity VARCHAR(20),
    Summary VARCHAR(600),
    Discovery_Method VARCHAR(100),
    Confidence VARCHAR(20),
    Data_Source VARCHAR(50)
);

INSERT INTO SECURITY_INCIDENT
(Incident_ID, Incident_Year, Incident_Month, Security_Incident,
 Incident_Type, Severity, Summary, Discovery_Method,
 Confidence, Data_Source)
VALUES

('I001',
 2025,
 1,
 'Phishing Attack',
 'Cyber Attack',
 'High',
 'Employee received a malicious phishing email containing a harmful link.',
 'Email Security Alert',
 'High',
 'VERIS'),

('I002',
 2025,
 2,
 'Credential Attack',
 'Unauthorized Access',
 'Critical',
 'Attacker used compromised credentials to access the domain controller.',
 'Authentication Monitoring',
 'High',
 'VERIS'),

('I003',
 2025,
 3,
 'Network Intrusion',
 'Intrusion',
 'Critical',
 'Unauthorized remote access was detected through network services.',
 'Firewall Monitoring',
 'Medium',
 'VERIS'),

('I004',
 2025,
 4,
 'PowerShell Attack',
 'Malware',
 'High',
 'PowerShell commands were executed on an employee endpoint.',
 'Endpoint Detection',
 'High',
 'VERIS'),

('I005',
 2025,
 5,
 'DNS Attack',
 'Network Attack',
 'Medium',
 'Suspicious network and DNS discovery activity was detected.',
 'DNS Monitoring',
 'Medium',
 'VERIS'),

('I006',
 2025,
 6,
 'Malware Intrusion',
 'Malware',
 'Critical',
 'Encoded malware activity followed by PowerShell and account discovery.',
 'Endpoint Detection',
 'High',
 'VERIS');


-- ============================================================
-- 6. ACTOR
-- ============================================================

CREATE TABLE ACTOR (
    Actor_ID VARCHAR(10) PRIMARY KEY,
    Actor_Name VARCHAR(100),
    Actor_Type VARCHAR(50),
    Actor_Variety VARCHAR(100),
    Motive VARCHAR(100),
    Group_ID VARCHAR(10),
    FOREIGN KEY (Group_ID)
        REFERENCES MITRE_GROUP(Group_ID)
);

INSERT INTO ACTOR
(Actor_ID, Actor_Name, Actor_Type, Actor_Variety, Motive, Group_ID)
VALUES

('A001',
 'APT1',
 'External',
 'Espionage Group',
 'Espionage',
 'G0006'),

('A002',
 'APT29',
 'External',
 'Espionage Group',
 'Espionage',
 'G0016'),

('A003',
 'APT3',
 'External',
 'Threat Group',
 'Espionage',
 'G0022'),

('A004',
 'OilRig',
 'External',
 'Threat Group',
 'Espionage',
 'G0049'),

('A005',
 'Wizard Spider',
 'External',
 'Cybercrime Group',
 'Financial',
 'G0102'),

('A006',
 'Unknown Attacker',
 'External',
 'Individual',
 'Financial',
 NULL);


-- ============================================================
-- 7. ASSET
-- ============================================================

CREATE TABLE ASSET (
    Asset_ID VARCHAR(10) PRIMARY KEY,
    Asset_Variety VARCHAR(100),
    Asset_Ownership VARCHAR(50),
    Asset_Status VARCHAR(50),
    Asset_Location VARCHAR(100)
);

INSERT INTO ASSET
(Asset_ID, Asset_Variety, Asset_Ownership,
 Asset_Status, Asset_Location)
VALUES

('AS01',
 'Server',
 'Organization',
 'Compromised',
 'Data Center'),

('AS02',
 'Endpoint',
 'Organization',
 'Compromised',
 'Finance Department'),

('AS03',
 'Network Device',
 'Organization',
 'Isolated',
 'Main Office'),

('AS04',
 'Database Server',
 'Organization',
 'Compromised',
 'Data Center'),

('AS05',
 'Employee Laptop',
 'Organization',
 'Compromised',
 'HR Department'),

('AS06',
 'Web Server',
 'Organization',
 'Under Investigation',
 'DMZ'),

('AS07',
 'Email Server',
 'Organization',
 'Compromised',
 'Mail Server Room'),

('AS08',
 'Cloud Server',
 'Organization',
 'Active',
 'Cloud Environment'),

('AS09',
 'Domain Controller',
 'Organization',
 'Compromised',
 'IT Department'),

('AS10',
 'Workstation',
 'Organization',
 'Isolated',
 'Operations Department');


-- ============================================================
-- 8. ATTACK_EVENT
-- ============================================================

CREATE TABLE ATTACK_EVENT (
    Event_ID VARCHAR(10) PRIMARY KEY,
    Incident_ID VARCHAR(10),
    Actor_ID VARCHAR(10),
    Asset_ID VARCHAR(10),
    Technique_ID VARCHAR(15),
    Software_ID VARCHAR(10),
    Event_Order INT,
    Action_Category VARCHAR(100),
    Action_Variety VARCHAR(100),
    Event_Description VARCHAR(500),

    FOREIGN KEY (Incident_ID)
        REFERENCES SECURITY_INCIDENT(Incident_ID),

    FOREIGN KEY (Actor_ID)
        REFERENCES ACTOR(Actor_ID),

    FOREIGN KEY (Asset_ID)
        REFERENCES ASSET(Asset_ID),

    FOREIGN KEY (Technique_ID)
        REFERENCES MITRE_TECHNIQUE(Technique_ID),

    FOREIGN KEY (Software_ID)
        REFERENCES MITRE_SOFTWARE(Software_ID)
);

INSERT INTO ATTACK_EVENT
(Event_ID, Incident_ID, Actor_ID, Asset_ID,
 Technique_ID, Software_ID, Event_Order,
 Action_Category, Action_Variety, Event_Description)
VALUES

('E001',
 'I001',
 'A001',
 'AS02',
 'T1566',
 'S0367',
 1,
 'Initial Access',
 'Phishing',
 'Malicious phishing email was delivered to an employee.'),

('E002',
 'I001',
 'A001',
 'AS02',
 'T1204.001',
 'S0367',
 2,
 'Execution',
 'Malicious Link',
 'Employee interacted with a malicious link.'),

('E003',
 'I002',
 'A002',
 'AS09',
 'T1078',
 NULL,
 1,
 'Defense Evasion',
 'Valid Accounts',
 'Compromised credentials were used for authentication.'),

('E004',
 'I002',
 'A002',
 'AS09',
 'T1003',
 NULL,
 2,
 'Credential Access',
 'Credential Dumping',
 'Credential information was targeted on the domain controller.'),

('E005',
 'I003',
 'A003',
 'AS03',
 'T1021',
 NULL,
 1,
 'Lateral Movement',
 'Remote Services',
 'Remote services were used to access the network device.'),

('E006',
 'I003',
 'A003',
 'AS01',
 'T1021.001',
 NULL,
 2,
 'Lateral Movement',
 'RDP',
 'Remote Desktop Protocol was used to access a server.'),

('E007',
 'I004',
 'A004',
 'AS05',
 'T1059.001',
 'S0363',
 1,
 'Execution',
 'PowerShell',
 'PowerShell was executed on the employee laptop.'),

('E008',
 'I004',
 'A004',
 'AS05',
 'T1059',
 'S0363',
 2,
 'Execution',
 'Command and Scripting',
 'Command and scripting activity was detected.'),

('E009',
 'I005',
 'A005',
 'AS06',
 'T1016.001',
 'S0597',
 1,
 'Discovery',
 'Network Discovery',
 'Internet connection information was collected.'),

('E010',
 'I005',
 'A005',
 'AS06',
 'T1087',
 NULL,
 2,
 'Discovery',
 'Account Discovery',
 'System account information was discovered.'),

('E011',
 'I006',
 'A006',
 'AS01',
 'T1027.013',
 'S0565',
 1,
 'Defense Evasion',
 'Obfuscated Files',
 'Encoded or obfuscated file activity was detected.'),

('E012',
 'I006',
 'A006',
 'AS01',
 'T1059.001',
 NULL,
 2,
 'Execution',
 'PowerShell',
 'PowerShell was executed after encoded file activity.'),

('E013',
 'I006',
 'A006',
 'AS09',
 'T1087',
 NULL,
 3,
 'Discovery',
 'Account Discovery',
 'Accounts were enumerated on the domain controller.'),

('E014',
 'I006',
 'A006',
 'AS09',
 'T1016.001',
 'S0597',
 4,
 'Discovery',
 'Internet Connection Discovery',
 'Network connection information was collected.');


-- ============================================================
-- 9. EVIDENCE_SOURCE
-- ============================================================

CREATE TABLE EVIDENCE_SOURCE (
    Evidence_ID VARCHAR(10) PRIMARY KEY,
    Incident_ID VARCHAR(10),
    Source_Name VARCHAR(200),
    Source_Type VARCHAR(50),
    Evidence_Description VARCHAR(500),

    FOREIGN KEY (Incident_ID)
        REFERENCES SECURITY_INCIDENT(Incident_ID)
);

INSERT INTO EVIDENCE_SOURCE
(Evidence_ID, Incident_ID, Source_Name,
 Source_Type, Evidence_Description)
VALUES

('EV001',
 'I001',
 'Email Gateway Logs',
 'Network Log',
 'Email metadata and malicious URL information.'),

('EV002',
 'I001',
 'Endpoint Security Logs',
 'Endpoint Log',
 'Endpoint records showing user interaction with the malicious link.'),

('EV003',
 'I002',
 'Authentication Logs',
 'Authentication Log',
 'Login records showing use of compromised credentials.'),

('EV004',
 'I003',
 'Firewall Logs',
 'Network Log',
 'Firewall records showing remote service connections.'),

('EV005',
 'I004',
 'Windows Event Logs',
 'System Log',
 'Windows logs showing PowerShell execution.'),

('EV006',
 'I005',
 'DNS Logs',
 'Network Log',
 'DNS records showing suspicious network activity.'),

('EV007',
 'I006',
 'Endpoint Detection System',
 'Endpoint Log',
 'Endpoint telemetry showing encoded malware activity.'),

('EV008',
 'I006',
 'Network Traffic Capture',
 'Network Evidence',
 'Captured network traffic related to account and connection discovery.');


-- ============================================================
-- 10. INCIDENT_RESPONSE
-- ============================================================

CREATE TABLE INCIDENT_RESPONSE (
    Response_ID VARCHAR(10) PRIMARY KEY,
    Incident_ID VARCHAR(10),
    Lead_Investigator VARCHAR(100),
    Response_Action VARCHAR(500),
    Response_Status VARCHAR(50),
    Resolution_Date DATE,
    Notes VARCHAR(500),

    FOREIGN KEY (Incident_ID)
        REFERENCES SECURITY_INCIDENT(Incident_ID)
);

INSERT INTO INCIDENT_RESPONSE
(Response_ID, Incident_ID, Lead_Investigator,
 Response_Action, Response_Status, Resolution_Date, Notes)
VALUES

('R001',
 'I001',
 'SOC Team',
 'Blocked malicious email and reset affected user credentials.',
 'Resolved',
 '2025-01-15',
 'User account monitored after remediation.'),

('R002',
 'I002',
 'Incident Response Team',
 'Disabled compromised accounts and reset authentication credentials.',
 'Resolved',
 '2025-02-20',
 'Domain controller reviewed for additional compromise.'),

('R003',
 'I003',
 'Network Security Team',
 'Blocked remote access and isolated affected network device.',
 'Contained',
 '2025-03-18',
 'Network traffic was monitored after containment.'),

('R004',
 'I004',
 'SOC Team',
 'Terminated PowerShell processes and isolated affected endpoint.',
 'Resolved',
 '2025-04-10',
 'Endpoint scan completed successfully.'),

('R005',
 'I005',
 'Security Operations Team',
 'Blocked suspicious network activity and reviewed DNS records.',
 'Resolved',
 '2025-05-22',
 'No additional suspicious DNS activity observed.'),

('R006',
 'I006',
 'Digital Forensics Team',
 'Collected forensic evidence and isolated compromised systems.',
 'Under Investigation',
 '2025-06-30',
 'Detailed forensic investigation is still in progress.');


-- ============================================================
-- DISPLAY ALL TABLES
-- ============================================================

SHOW TABLES;


-- ============================================================
-- DISPLAY DATA FROM ALL TABLES
-- ============================================================

SELECT * FROM MITRE_GROUP;

SELECT * FROM MITRE_TECHNIQUE;

SELECT * FROM MITRE_SOFTWARE;

SELECT * FROM SECURITY_INCIDENT;

SELECT * FROM ACTOR;

SELECT * FROM ASSET;

SELECT * FROM ATTACK_EVENT;

SELECT * FROM EVIDENCE_SOURCE;

SELECT * FROM INCIDENT_RESPONSE;
