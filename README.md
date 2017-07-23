# vv
Vintage Values - Udacity catalog project

Vintage Values (VV) is a catalog project for the Udacity full stack nanodegree program that demonstrates use
of database operations and third party authentication. It is designed under the rubric requirements, so it
operates in ways that would not be reasonable in a system designed for the public, such as being able to delete content
after another user has added additional content to it.

REQUIREMENTS:
Python3,
Google account,
flask, sqlalchemy, oauth2client libraries

SETUP:
Run create_vv_db.py,
Run populate_vv_db.py,
Run vv.py

GUIDE:
User can add/delete/edit own content only.
User must be logged in via Google to add or edit content.
A JSON endpoint is available to retrieve the wine data by producer ID, i.e. localhost:5000/JSON/1

