-- Security Incident Attack-Path Database
-- Query catalogue compiled from the team's DBMS project report.
-- Database engine: MySQL 8.x (stored routines use MySQL syntax).
--
-- IMPORTANT:
-- 1) This is a query catalogue, not a guaranteed one-click setup script.
-- 2) Run schema/seed scripts first, in foreign-key dependency order.
-- 3) Some statements are demonstrations (e.g. intentionally invalid trigger test,
--    transaction/locking examples, or proposed Member 4 commands).
-- 4) The report identifies the project's records as illustrative sample data.
-- 5) Check the section headings before running routines/views if an object already exists.
--
-- Query example 1
CREATE TABLE SECURITY_INCIDENT (
Incident_ID       VARCHAR(10) PRIMARY KEY,
Incident_Year     INT,
Incident_Month    INT,
Security_Incident VARCHAR(30),
Incident_Type     VARCHAR(50),
Severity          VARCHAR(20),
Summary           VARCHAR(600),
Discovery_Method  VARCHAR(100),
Confidence        VARCHAR(20),
Data_Source       VARCHAR(50)
);

-- Query example 2
CREATE TABLE ACTOR (
Actor_ID      VARCHAR(10) PRIMARY KEY,
Actor_Name    VARCHAR(100),
Actor_Type    VARCHAR(50),
Actor_Variety VARCHAR(100),
Motive        VARCHAR(100),
Group_ID      VARCHAR(10),
FOREIGN KEY (Group_ID) REFERENCES MITRE_GROUP(Group_ID)
);

-- Query example 3
CREATE TABLE ATTACK_EVENT (
Event_ID          VARCHAR(10) PRIMARY KEY,
Incident_ID       VARCHAR(10),
Actor_ID          VARCHAR(10),
Asset_ID          VARCHAR(10),
Technique_ID      VARCHAR(15),
Software_ID       VARCHAR(10),
Event_Order       INT,
Action_Category   VARCHAR(100),
Action_Variety    VARCHAR(100),
Event_Description VARCHAR(500),
FOREIGN KEY (Incident_ID)  REFERENCES SECURITY_INCIDENT(Incident_ID),
FOREIGN KEY (Actor_ID)     REFERENCES ACTOR(Actor_ID),
FOREIGN KEY (Asset_ID)     REFERENCES ASSET(Asset_ID),
FOREIGN KEY (Technique_ID) REFERENCES MITRE_TECHNIQUE(Technique_ID),
FOREIGN KEY (Software_ID)  REFERENCES MITRE_SOFTWARE(Software_ID)
);

-- Query example 4
SELECT Incident_ID, Security_Incident, Incident_Type, Severity
FROM SECURITY_INCIDENT
WHERE Severity IN ('High', 'Critical');

-- Query example 5
SELECT *
FROM SECURITY_INCIDENT
WHERE Severity = 'Critical';

-- Query example 6
SELECT Incident_ID, Security_Incident, Severity
FROM SECURITY_INCIDENT
WHERE Severity = 'Critical';

-- Query example 7
SELECT A.Actor_Name, AE.Incident_ID, AE.Event_ID
FROM ACTOR A
JOIN ATTACK_EVENT AE ON A.Actor_ID = AE.Actor_ID
WHERE A.Actor_Type = 'External';

-- Query example 8
SELECT AE.Event_ID, AE.Incident_ID, MS.Software_Name, MT.Technique_Name
FROM ATTACK_EVENT AE
JOIN MITRE_SOFTWARE MS  ON AE.Software_ID  = MS.Software_ID
JOIN MITRE_TECHNIQUE MT ON AE.Technique_ID = MT.Technique_ID;

-- Query example 9
SELECT Event_ID, Incident_ID, Technique_ID
FROM ATTACK_EVENT
WHERE Software_ID IS NULL;

-- Query example 10
SELECT AE.Incident_ID, SI.Security_Incident, SI.Severity, AE.Event_Order,
A.Actor_Name, ASSET.Asset_Variety, MT.Technique_ID, MT.Technique_Name,

-- Query example 11
SELECT SI.Incident_ID, SI.Security_Incident, SI.Severity, AE.Event_Order,
A.Actor_Name, ASSET.Asset_Variety, MT.Technique_ID, MT.Technique_Name,

-- Query example 12
SELECT AE.Event_Order, MT.Technique_ID, MT.Technique_Name,

-- Query example 13
SELECT Incident_ID, COUNT(*) AS Number_of_Attack_Events
FROM ATTACK_EVENT
GROUP BY Incident_ID;

-- Query example 14
SELECT Incident_ID, COUNT(*) AS Attack_Event_Count
FROM ATTACK_EVENT
GROUP BY Incident_ID
HAVING COUNT(*) > 1;

-- Query example 15
SELECT Actor_ID, COUNT(*) AS Total_Attacks
FROM ATTACK_EVENT
GROUP BY Actor_ID;

-- Query example 16
SELECT A.Actor_Name, COUNT(AE.Event_ID) AS Total_Attacks
FROM ACTOR A
JOIN ATTACK_EVENT AE ON A.Actor_ID = AE.Actor_ID
GROUP BY A.Actor_ID, A.Actor_Name;

-- Query example 17
SELECT A.Actor_Name, COUNT(AE.Event_ID) AS Total_Attacks
FROM ACTOR A
JOIN ATTACK_EVENT AE ON A.Actor_ID = AE.Actor_ID
GROUP BY A.Actor_ID, A.Actor_Name
HAVING COUNT(AE.Event_ID) > 1;

-- Query example 18
SELECT Incident_ID, COUNT(*) AS Total_Steps
FROM ATTACK_EVENT
GROUP BY Incident_ID
HAVING COUNT(*) > 2;

-- Query example 19
SELECT Incident_ID, COUNT(*) AS Attack_Event_Count
FROM ATTACK_EVENT
GROUP BY Incident_ID
HAVING COUNT(*) > (

-- Query example 20
SELECT AVG(Event_Count)
FROM (

-- Query example 21
SELECT COUNT(*) AS Event_Count
FROM ATTACK_EVENT
GROUP BY Incident_ID
) AS Attack_Counts
);

-- Query example 22
SELECT Actor_Name
FROM ACTOR
WHERE Actor_ID IN (

-- Query example 23
SELECT Actor_ID
FROM ATTACK_EVENT
WHERE Incident_ID IN (

-- Query example 24
SELECT Incident_ID
FROM SECURITY_INCIDENT
WHERE Severity = 'Critical'
)
);

-- Query example 25
SELECT Incident_ID, Security_Incident
FROM SECURITY_INCIDENT
WHERE Incident_ID IN (

-- Query example 26
SELECT Incident_ID
FROM ATTACK_EVENT
WHERE Technique_ID = 'T1059.001'
);

-- Query example 27
SELECT SI.Incident_ID, SI.Security_Incident, SI.Severity
FROM SECURITY_INCIDENT SI
WHERE SI.Incident_ID IN (

-- Query example 28
SELECT Incident_ID
FROM ATTACK_EVENT
WHERE Technique_ID = 'T1078'
);

-- Query example 29
SELECT Actor_Name
FROM ACTOR
WHERE Actor_ID = (

-- Query example 30
SELECT Actor_ID
FROM ATTACK_EVENT
WHERE Incident_ID = 'I006'
LIMIT 1
);

-- Query example 31
SELECT COUNT(*) AS Total_Incidents FROM SECURITY_INCIDENT;

-- Query example 32
SELECT MAX(Event_Order) AS Maximum_Attack_Steps FROM ATTACK_EVENT;

-- Query example 33
SELECT MIN(Event_Order) AS Minimum_Attack_Order FROM ATTACK_EVENT;

-- Query example 34
SELECT AVG(Event_Order) AS Average_Attack_Order FROM ATTACK_EVENT;

-- Query example 35
DELIMITER //

-- Query example 36
CREATE FUNCTION GetAttackStepCount(p_incident_id VARCHAR(10))
RETURNS INT
DETERMINISTIC
BEGIN
DECLARE step_count INT;
SELECT COUNT(*)
INTO step_count
FROM ATTACK_EVENT
WHERE Incident_ID = p_incident_id;
RETURN step_count;
END //

-- Query example 37
DELIMITER ;

-- Query example 38
SELECT GetAttackStepCount('I006') AS Attack_Steps;

-- Query example 39
CREATE PROCEDURE ShowAttackPath(IN p_incident_id VARCHAR(10))
BEGIN
SELECT AE.Event_Order, A.Actor_Name, ASSET.Asset_Variety,
MT.Technique_ID, MT.Technique_Name, MS.Software_Name,

-- Query example 40
CALL ShowAttackPath('I006');

-- Query example 41
CREATE TRIGGER CheckAttackOrder
BEFORE INSERT ON ATTACK_EVENT
FOR EACH ROW
BEGIN
IF NEW.Event_Order <= 0 THEN

-- Query example 42
SET MESSAGE_TEXT = 'Event order must be greater than zero';
END IF;
END //

-- Query example 43
INSERT INTO ATTACK_EVENT
(Event_ID, Incident_ID, Actor_ID, Asset_ID, Technique_ID,
Software_ID, Event_Order, Action_Category, Action_Variety, Event_Description)
VALUES
('E099', 'I001', 'A001', 'AS02', 'T1566',
'S0367', 0, 'Initial Access', 'Phishing', 'Invalid attack order');

-- Query example 44
CREATE VIEW AttackPathView AS

-- Query example 45
SELECT AE.Event_ID, AE.Incident_ID, SI.Security_Incident, SI.Severity,
AE.Event_Order, A.Actor_Name, ASSET.Asset_Variety, MT.Technique_Name,

-- Query example 46
SELECT * FROM AttackPathView; returns the same 14 rows shown in section 1.5. The view can be filtered like a table:

-- Query example 47
SELECT *
FROM AttackPathView
WHERE Incident_ID = 'I006'
ORDER BY Event_Order;

-- Query example 48
CREATE TABLE ASSET (
Asset_ID        VARCHAR(10) PRIMARY KEY,
Asset_Variety   VARCHAR(100),
Asset_Ownership VARCHAR(50),
Asset_Status    VARCHAR(50),
Asset_Location  VARCHAR(100)
);

-- Query example 49
SELECT A.Asset_ID, A.Asset_Variety, A.Asset_Status,
T.Technique_ID, T.Technique_Name,

-- Query example 50
SELECT A.Asset_ID, A.Asset_Variety, COUNT(AE.Event_ID) AS Number_of_Attacks
FROM ASSET A
JOIN ATTACK_EVENT AE ON A.Asset_ID = AE.Asset_ID
GROUP BY A.Asset_ID, A.Asset_Variety;

-- Query example 51
SELECT A.Asset_ID, A.Asset_Variety, COUNT(AE.Event_ID) AS Number_of_Attacks
FROM ASSET A
JOIN ATTACK_EVENT AE ON A.Asset_ID = AE.Asset_ID
GROUP BY A.Asset_ID, A.Asset_Variety
HAVING COUNT(AE.Event_ID) > 1;

-- Query example 52
SELECT *
FROM ASSET
WHERE Asset_ID IN (

-- Query example 53
SELECT Asset_ID
FROM ATTACK_EVENT
WHERE Incident_ID IN (

-- Query example 54
SELECT COUNT(*) AS Total_Assets FROM ASSET;

-- Query example 55
SELECT COUNT(DISTINCT Asset_Variety) AS Asset_Types FROM ASSET;

-- Query example 56
SELECT Asset_Variety, COUNT(*) AS Total
FROM ASSET
GROUP BY Asset_Variety
ORDER BY Total DESC;

-- Query example 57
CREATE FUNCTION GetAssetAttackCount(p_asset_id VARCHAR(10))
RETURNS INT
DETERMINISTIC
BEGIN
DECLARE attack_count INT;
SELECT COUNT(*) INTO attack_count
FROM ATTACK_EVENT
WHERE Asset_ID = p_asset_id;
RETURN attack_count;
END //

-- Query example 58
SELECT GetAssetAttackCount('AS01');

-- Query example 59
CREATE PROCEDURE ShowAssetAttacks(IN p_asset_id VARCHAR(10))
BEGIN
SELECT A.Asset_ID, A.Asset_Variety, T.Technique_ID, T.Technique_Name,

-- Query example 60
CALL ShowAssetAttacks('AS01');

-- Query example 61
CREATE TRIGGER CheckAssetStatus
BEFORE INSERT ON ASSET
FOR EACH ROW
BEGIN
IF NEW.Asset_Status NOT IN
('Active','Compromised','Isolated','Under Investigation') THEN

-- Query example 62
SET MESSAGE_TEXT = 'Invalid asset status';
END IF;
END //

-- Query example 63
INSERT INTO ASSET
VALUES ('AS11', 'Test Server', 'Organization', 'UnknownStatus', 'Test Location');

-- Query example 64
CREATE VIEW AssetAttackView AS

-- Query example 65
SELECT * FROM AssetAttackView;

-- Query example 66
SELECT e.Evidence_ID, e.Incident_ID, si.Incident_Type, si.Severity,

-- Query example 67
SELECT *
FROM SECURITY_INCIDENT
WHERE Severity = 'High'
ORDER BY Incident_ID;

-- Query example 68
SELECT *
FROM SECURITY_INCIDENT
WHERE Incident_Type LIKE '%Phishing%';

-- Query example 69
USE securityattackpathdb;

-- Query example 70
SELECT a.Actor_ID, a.Actor_Name
FROM ACTOR a
LEFT JOIN ATTACK_EVENT ae
ON a.Actor_ID = ae.Actor_ID
WHERE ae.Event_ID IS NULL;

-- Query example 71
SELECT si.Incident_ID, ae.Event_ID, ac.Actor_Name,

-- Query example 72
SELECT DISTINCT si.Incident_ID, si.Incident_Type,

-- Query example 73
SELECT Incident_ID, COUNT(*) AS Evidence_Count
FROM EVIDENCE_SOURCE
GROUP BY Incident_ID
ORDER BY Evidence_Count DESC;

-- Query example 74
SELECT Incident_ID, COUNT(*) AS Attack_Event_Count
FROM ATTACK_EVENT
GROUP BY Incident_ID
HAVING COUNT(*) > 2
ORDER BY Attack_Event_Count DESC;

-- Query example 75
CREATE VIEW VW_INVESTIGATION_REPORT AS

-- Query example 76
SELECT si.Incident_ID, si.Incident_Type, si.Severity,
ir.Lead_Investigator AS Security_Analyst,

-- Query example 77
SELECT Incident_ID, Incident_Type, Severity,

-- Query example 78
SELECT Incident_ID, Incident_Type, Severity, Summary
FROM SECURITY_INCIDENT
WHERE Incident_ID IN (

-- Query example 79
SELECT Incident_ID
FROM EVIDENCE_SOURCE
GROUP BY Incident_ID
HAVING COUNT(*) > 1
);

-- Query example 80
DELIMITER $$

-- Query example 81
CREATE FUNCTION fn_evidence_count(p_incident_id VARCHAR(10))
RETURNS INT
READS SQL DATA
BEGIN
DECLARE v_count INT DEFAULT 0;

-- Query example 82
SELECT COUNT(*)
INTO v_count
FROM EVIDENCE_SOURCE
WHERE Incident_ID = p_incident_id;

-- Query example 83
CREATE PROCEDURE sp_investigation_report(IN p_incident_id VARCHAR(10))
BEGIN
SELECT Incident_ID, Incident_Type, Severity, Summary
FROM SECURITY_INCIDENT
WHERE Incident_ID = p_incident_id;
END$$

-- Query example 84
CALL sp_investigation_report('I006');

-- Query example 85
CREATE TRIGGER trg_evidence_after_insert
AFTER INSERT ON EVIDENCE_SOURCE
FOR EACH ROW
BEGIN
INSERT INTO EVIDENCE_AUDIT
(Evidence_ID, Action_Type, New_Incident_ID,
New_Source_Name, New_Source_Type,
New_Evidence_Description, Changed_By)
VALUES
(NEW.Evidence_ID, 'INSERT', NEW.Incident_ID,
NEW.Source_Name, NEW.Source_Type,
NEW.Evidence_Description, CURRENT_USER());
END$$

-- Query example 86
UPDATE EVIDENCE_SOURCE

-- Query example 87
SET Source_Name = 'Updated Evidence Source'
WHERE Evidence_ID = 'EV001';

-- Query example 88
DELETE FROM EVIDENCE_SOURCE
WHERE Evidence_ID = 'EV001';

-- Query example 89
SELECT mt.Tactic,

-- Query example 90
SELECT *
FROM INCIDENT_RESPONSE
WHERE Response_Status <> 'Resolved'
ORDER BY Incident_ID;

-- Query example 91
SELECT Response_ID, Incident_ID, Lead_Investigator, Response_Action
FROM INCIDENT_RESPONSE
WHERE Lead_Investigator LIKE '%Team%';

-- Query example 92
SELECT si.Incident_ID, si.Incident_Type, si.Severity
FROM SECURITY_INCIDENT si
LEFT JOIN INCIDENT_RESPONSE ir
ON si.Incident_ID = ir.Incident_ID
WHERE ir.Response_ID IS NULL;

-- Query example 93
SELECT Response_Status, COUNT(*) AS Response_Count
FROM INCIDENT_RESPONSE
GROUP BY Response_Status
ORDER BY Response_Count DESC;

-- Query example 94
SELECT Lead_Investigator, COUNT(*) AS Responses_Led
FROM INCIDENT_RESPONSE
GROUP BY Lead_Investigator
HAVING COUNT(*) > 1
ORDER BY Responses_Led DESC;

-- Query example 95
CREATE VIEW VW_RESPONSE_STATUS AS SELECT     si.Incident_ID,     si.Incident_Type,     si.Severity,     ir.Response_ID,     ir.Lead_Investigator AS Security_Analyst,     ir.Response_Action,     ir.Response_Status,     ir.Resolution_Date FROM SECURITY_INCIDENT si
LEFT JOIN INCIDENT_RESPONSE ir
ON ir.Incident_ID = si.Incident_ID;

-- Query example 96
SELECT Response_ID, Incident_ID, Lead_Investigator, Response_Status
FROM INCIDENT_RESPONSE
WHERE Incident_ID IN (

-- Query example 97
SELECT Incident_ID
FROM ATTACK_EVENT
GROUP BY Incident_ID
HAVING COUNT(*) > 2
);

-- Query example 98
CREATE FUNCTION fn_open_response_count(p_incident_id VARCHAR(10))
RETURNS INT
READS SQL DATA
BEGIN
DECLARE v_count INT DEFAULT 0;
SELECT COUNT(*)
INTO v_count
FROM INCIDENT_RESPONSE
WHERE Incident_ID = p_incident_id
AND Response_Status <> 'Resolved';
RETURN v_count;
END$$

-- Query example 99
SELECT fn_open_response_count('I006') AS Open_Responses;

-- Query example 100
CREATE PROCEDURE sp_update_response_status(
IN p_response_id VARCHAR(10),
IN p_new_status  VARCHAR(50))
BEGIN
IF p_new_status = 'Resolved' THEN
UPDATE INCIDENT_RESPONSE
SET Response_Status = p_new_status,
Resolution_Date = CURDATE()
WHERE Response_ID = p_response_id;
ELSE
UPDATE INCIDENT_RESPONSE
SET Response_Status = p_new_status
WHERE Response_ID = p_response_id;
END IF;
SELECT Response_ID, Incident_ID, Lead_Investigator,
Response_Status, Resolution_Date
FROM INCIDENT_RESPONSE
WHERE Response_ID = p_response_id;
END$$

-- Query example 101
CREATE TABLE IF NOT EXISTS RESPONSE_AUDIT (
Audit_ID         INT AUTO_INCREMENT PRIMARY KEY,
Response_ID      VARCHAR(10),
Incident_ID      VARCHAR(10),
Action_Type      VARCHAR(10) NOT NULL,
Old_Status       VARCHAR(50),
New_Status       VARCHAR(50),
Old_Investigator VARCHAR(100),
New_Investigator VARCHAR(100),
Changed_By       VARCHAR(100),

-- Query example 102
CREATE TRIGGER trg_response_after_update
AFTER UPDATE ON INCIDENT_RESPONSE
FOR EACH ROW
BEGIN
IF NOT (OLD.Response_Status <=> NEW.Response_Status)
OR NOT (OLD.Lead_Investigator <=> NEW.Lead_Investigator) THEN
INSERT INTO RESPONSE_AUDIT
(Response_ID, Incident_ID, Action_Type,
Old_Status, New_Status,
Old_Investigator, New_Investigator, Changed_By)
VALUES
(NEW.Response_ID, NEW.Incident_ID, 'UPDATE',
OLD.Response_Status, NEW.Response_Status,
OLD.Lead_Investigator, NEW.Lead_Investigator,
CURRENT_USER());
END IF;
END$$

-- Query example 103
INSERT INTO INCIDENT_RESPONSE
(Response_ID, Incident_ID, Lead_Investigator, Response_Action,
Response_Status, Resolution_Date, Notes)
VALUES
('R999', 'I004', 'SOC Team', 'Test - isolate affected host',
'Open', NULL, 'Member 4 demo record');
-- 2. Change the status

-- Query example 104
CALL sp_update_response_status('R999', 'In Progress');
-- 3. Resolve the incident

-- Query example 105
CALL sp_update_response_status('R999', 'Resolved');
-- 4. Check the audit trail written by the trigger

-- Query example 106
SELECT Audit_ID, Response_ID, Old_Status, New_Status, Changed_By
FROM RESPONSE_AUDIT
ORDER BY Audit_ID;

-- Query example 107
START TRANSACTION;

-- Query example 108
UPDATE INCIDENT_RESPONSE

-- Query example 109
SET Response_Status = 'Escalated'
WHERE Response_ID = 'R999';

-- Query example 110
SELECT Response_ID, Response_Status
FROM INCIDENT_RESPONSE WHERE Response_ID = 'R999';

-- Query example 111
ROLLBACK;

-- Query example 112
SELECT Response_ID, Response_Status
FROM INCIDENT_RESPONSE WHERE Response_ID = 'R999';
-- Part B: SAVEPOINT keeps one change and undoes the next

-- Query example 113
SET Notes = 'Reviewed by SOC lead'
WHERE Response_ID = 'R999';

-- Query example 114
SAVEPOINT after_notes;

-- Query example 115
ROLLBACK TO SAVEPOINT after_notes;

-- Query example 116
COMMIT;

-- Query example 117
SELECT Response_ID, Response_Status, Notes
FROM INCIDENT_RESPONSE WHERE Response_ID = 'R999';

-- Query example 118
SELECT Response_ID, Lead_Investigator, Response_Status
FROM INCIDENT_RESPONSE
WHERE Response_ID = 'R999'
FOR UPDATE;

-- Query example 119
SET Lead_Investigator = 'Senior SOC Analyst'
WHERE Response_ID = 'R999';
-- SESSION 2 (second terminal, while Session 1 is still open)

-- Query example 120
SET Response_Status = 'Escalated'
WHERE Response_ID = 'R999';      -- waits for Session 1
-- SESSION 1

-- Query example 121
COMMIT;                          -- Session 2 can now continue
-- SESSION 2

-- Query example 122
SELECT @@transaction_isolation;

-- Query example 123
SELECT * FROM VW_RESPONSE_STATUS ORDER BY Incident_ID;
4.12.3 Function test (proposed)

-- Query example 124
SELECT fn_open_response_count('I004') AS Open_Responses;
4.12.4 Clean-up of the test data (proposed)

-- Query example 125
DELETE FROM INCIDENT_RESPONSE WHERE Response_ID = 'R999';
-- optional: also clear the demonstration rows from the audit table

-- Query example 126
DELETE FROM RESPONSE_AUDIT WHERE Response_ID = 'R999';
After the clean-up INCIDENT_RESPONSE again holds the 6 rows inserted by dbms.sql, and Command 4 again returns an empty set. The DELETE does not fire the audit trigger, which is an AFTER UPDATE trigger.
