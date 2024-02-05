# PHP-MYSQL-User-Login-System---SQL-Injection

Affected Web App: https://github.com/keerti1924/PHP-MYSQL-User-Login-System

Title: SQL Injection

Affected Component: /edit.php

CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

CVSS 3.1 Score: 8.3 (self - rated with the help of online CVSS calculator)

Impact: SQL injection poses a severe threat to database-driven applications, allowing unauthorized access and potential compromise of sensitive data. This vulnerability enables data manipulation, leading to integrity issues, and allows for the extraction of confidential information, including usernames and passwords. Additionally, SQL injection can be exploited for denial-of-service attacks by executing resource-intensive queries. To mitigate these risks, developers should prioritize secure coding practices, implement parameterized queries, and conduct regular security audits to proactively address vulnerabilities.

Proof of Concept: To reproduce this attack, an attacker can inject SQL Injection payloads like:' '# ' to break out of the SQL query in the backend. This will result to changing the usernames for all users of the webapp.
![image](https://github.com/omarexala/PHP-MYSQL-User-Login-System---SQL-Injection/assets/159004359/2511e11e-6afb-4f98-996e-90df0e25143e)

Remediation: To address SQL injection vulnerabilities, adopt parameterized queries, ensuring user input is treated as data, not executable code. Implement strict input validation, utilize stored procedures and prepared statements, and adhere to the principle of least privilege for database accounts. Deploy a Web Application Firewall (WAF) to filter and block common SQL injection patterns. Conduct regular security audits and code reviews, and employ Database Activity Monitoring (DAM) tools to detect and respond to suspicious database activity. Ongoing developer education on secure coding practices is crucial to maintaining a robust defense against SQL injection attacks.
