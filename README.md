CVE-NVD Vulnerabilities Analysis
================================

Project Description
-------------------
This project for analysis of reported vulnerabilities for the software's running over internet or cyber
physical infrastructure. The reported vulnerabilities are based on available open repositories for reported 
critical infrastructure software for example https://nvd.nist.gov/.

Project Work
------------
The project work is conducted for generating report that shows the following analysis points:
1. Total reported vulnerabilities across year.
2. Total reported vulnerabilities for CPS component RTU, MTU, PLC, HMI.
3. Total average cvss score for reported vulnerabilities of CPS components above.
4. Comparison of average CPS score vs the frequency of occurrence for reported vulnerabilities about CPS components.
5. Check manually description of 3 CVE ID for selected year.

All above analysis requirements are handled graphically also using plotly and matplotlib.

'Note: The first time execution is slow because it will try to pull zipped vulnerabilities for all years from open source database.'

Project Architecture
--------
The project is based on MVC (Model, View and Controller) framework.
This nvd_view is model part of the system which interacts with interal and external databases.
Sends response towards controller with relevant data as per use case and then
the controller based on use case creates response with appropriate
data and status code towards view


    