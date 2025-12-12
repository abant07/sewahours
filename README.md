## Sewa International Volunteer Hour Tracking Web Application

Python Flask application for supporting the Sewa International Non Profit (https://www.sewausa.org/). Current practices for keeping track of volunteer hours at Sewa International have been to fill out Google Forms declaring how many volunteer hours volunteers have spent for a given event over the course of a year. These forms would be manually reviewed by Sewa Chapter Coordinators to validate whether hours are true or fradulent. Hours are then transferred to a Excel Spreadsheet to tally. Depending on the number of hours a volunteer dedicates over 1 year period, they are eligible to earn a Presidential Volunteer Service Award (https://presidentialserviceawards.gov/).

With Sewa Hours, we aim to automate this process using a basic Python Flask Application built entirely in native HTML and CSS for the frontend, and Python for the backend. This web application was built with Python 3.7:

To get started:

Set up a python venv (alternatively you can use conda to install a environment for a dedicated Python version)

`python3 -m venv venv` 


`source activate venv/bin/activate`


Install dependencies


`pip install -r requirements.txt` 

Run application
`python application.py`
