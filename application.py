import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import hashlib
from datetime import date, timedelta, datetime
import secrets

def numOfDays(date1, date2):
    return (date2-date1).days

application = Flask(__name__)
#flask application creates a secret key
application.secret_key = secrets.token_hex(16)
# puts a timer on how long a user can be in a session. after time, user is sent to home page to restart session
application.permanent_session_lifetime = timedelta(minutes=10)

#sessions are created and if user logs out to go to home page, the loggedin session is popped
@application.route('/')
def home():
  if "loggedin" in session:
    session.pop("loggedin")
  session["code"] = True
  session["volunteer"] = True
  session["admin"] = True
  return render_template('sewawebsitehome.html')

#when user logs out, this pops all the session and redirects to home page
@application.route('/logout')
def logout():
  session.pop("loggedin")
  if "admin" in session:
    session.pop("admin")
    if "superadmin" in session:
      session.pop("superadmin")
  elif "volunteer" in session:
    session.pop("volunteer")
  return redirect(url_for('home'))

#if user types in signup url when signed in, it signs them out
@application.route('/signup')
def signup():
  if "loggedin" in session:
    session.pop("loggedin")
  return render_template('sewawebsitesignup.html')

#this will end superadmin session so that no one can access it but me
@application.route('/loghours')
def logHours():
  if "loggedin" in session and "volunteer" in session:
    return render_template('sewawebsiteloghours.html')
  else:
    return redirect(url_for('home'))

@application.route('/manageadmins')
def manageAdmins():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsitemanageadmins.html')
  else:
    return redirect(url_for('home'))

@application.route('/reinstateadmins')
def reinstateAdmins():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsitereinstate.html')
  else:
    return redirect(url_for('home'))

@application.route('/addevents')
def addEvents():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsiteaddevents.html')
  else:
    return redirect(url_for('home'))

@application.route('/addcategory')
def addCategory():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsiteaddcategory.html')
  else:
    return redirect(url_for('home'))

@application.route('/removeevents')
def removeEvents():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsiteremoveevents.html')
  else:
    return redirect(url_for('home'))

@application.route('/removecategory')
def removeCategory():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsiteremovecategory.html')
  else:
    return redirect(url_for('home'))

@application.route('/adminprofile')
def adminProfile():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsiteprofileadmin.html')
  else:
    return redirect(url_for('home'))

@application.route('/profile')
def volunteerProfile():
  if "loggedin" in session and "volunteer" in session:
    return render_template('sewawebsiteprofile.html')
  else:
    return redirect(url_for('home'))

@application.route('/adminhome')
def adminHome():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsiteadmin.html')
  else:
    return redirect(url_for('home'))

@application.route('/approvedhours')
def approvedHours():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsiteapproved.html')
  else:
    return redirect(url_for('home'))

@application.route('/certifiedhours')
def certifiedHours():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsitecertified.html')
  else:
    return redirect(url_for('home'))

@application.route('/rejectedhours')
def rejectedHours():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsiterejected.html')
  else:
    return redirect(url_for('home'))

@application.route('/unapprovedhours')
def unapprovedHours():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsiteunapproved.html')
  else:
    return redirect(url_for('home'))

@application.route('/yearend')
def yearendHours():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsitemedals.html')
  else:
    return redirect(url_for('home'))

@application.route('/certify')
def certify():
  if "loggedin" in session and "admin" in session:
    return render_template('sewawebsitecertify.html')
  else:
    return redirect(url_for('home'))

@application.route('/forgotpass')
def forgot():
  if "loggedin" in session:
    session.pop("loggedin")
  if "code" in session:
    return render_template('sewawebsiteforgotmessage.html')
  else:
    return redirect(url_for('home'))

@application.route('/code')
def code():
  if "loggedin" in session:
    session.pop("loggedin")
  return render_template('sewawebsitecode.html')

#only whenn user enters verification code and email can they access this page. if they didnt enter email, they can access, but wont work
@application.route('/change')
def change():
  if "loggedin" in session:
    session.pop("loggedin")
  if "code" in session:
    session.pop("code")
    return render_template('sewawebsitechangepass.html')
  else:
    return redirect(url_for('home'))

#only superadmin(me) can access this page
@application.route("/sql")
def sqlCommand():
  if "admin" in session and "superadmin" in session and "loggedin" in session:
    return render_template("sewawebsiteSQLeditor.html")
  else:
    return redirect(url_for("home"))



##### METHODS ######


#this will take the username of a user and appropriatly set a hashed username to then display in local storage
@application.route('/hashing', methods=['POST'])
def hashing():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    username = str(dataGet[0]["username"])

    salt = "p@$$1NgV@R!@B1Es"
    dataBase_username = username+salt
    hashed = hashlib.md5(dataBase_username.encode())
    hashed_username = hashed.hexdigest()

    volunteer_username = cursor.execute("SELECT COUNT(volunteerUsername) FROM volunteers WHERE volunteerUsername = ?", (username,),).fetchall()
    admin_username = cursor.execute("SELECT COUNT(adminUsername) FROM admins WHERE adminUsername = ?", (username,),).fetchall()

    if volunteer_username == [(1,)]:
      cursor.execute("UPDATE volunteers SET hashedUsername = ? WHERE volunteerUsername = ?", (hashed_username, username))
      connection.commit()
      connection.close()
      return jsonify({"hashed" : hashed_username})
    elif admin_username == [(1,)]:
      cursor.execute("UPDATE admins SET hashedUsername = ? WHERE adminUsername = ?", (hashed_username, username))
      connection.commit()
      connection.close()
      return jsonify({"hashed" : hashed_username})
    else:
      connection.close()
      return jsonify({})

# this will take a email from a user and hashe it and store it in database to store in local storage. used for forgot password
@application.route('/hashingtwo', methods=['POST'])
def hashingtwo():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    email = str(dataGet[0]["email"])

    salt = "p@$$1NgV@R!@B1Es"
    dataBase_email = email+salt
    hashed = hashlib.md5(dataBase_email.encode())
    hashed_email = hashed.hexdigest()

    volunteer_email = cursor.execute("SELECT COUNT(volunteerEmail) FROM volunteers WHERE volunteerEmail = ?", (email,),).fetchall()
    admin_email = cursor.execute("SELECT COUNT(adminEmail) FROM admins WHERE adminEmail = ?", (email,),).fetchall()

    if volunteer_email == [(1,)]:
      cursor.execute("UPDATE volunteers SET hashedEmail = ? WHERE volunteerEmail = ?", (hashed_email, email))
      connection.commit()
      connection.close()
      return jsonify({"hashed" : hashed_email})
    elif admin_email == [(1,)]:
      cursor.execute("UPDATE admins SET hashedEmail = ? WHERE adminEmail = ?", (hashed_email, email))
      connection.commit()
      connection.close()
      return jsonify({"hashed" : hashed_email})
    else:
      connection.close()
      return jsonify({})

# this gets the hashed email and finds the real email and uses it in transactions in app
@application.route('/gethashedtwo', methods=['POST'])
def getHashedtwo():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    email = str(dataGet[0]["email"])

    hashed_v = cursor.execute("SELECT volunteerEmail FROM volunteers WHERE hashedEmail = ?", (email,),).fetchall()
    hashed_a = cursor.execute("SELECT adminEmail FROM admins WHERE hashedEmail = ?", (email,),).fetchall()

    if hashed_v != []:
      return jsonify({"unhash" : hashed_v[0][0]})
    else:
      return jsonify({"unhash" : hashed_a[0][0]})

# this gets the hashed username and converts it into real username to use in update statments
@application.route('/gethashed', methods=['POST'])
def getHashed():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    username = str(dataGet[0]["username"])

    hashed_v = cursor.execute("SELECT volunteerUsername FROM volunteers WHERE hashedUsername = ?", (username,),).fetchall()
    hashed_a = cursor.execute("SELECT adminUsername FROM admins WHERE hashedUsername = ?", (username,),).fetchall()


    if hashed_v != []:
      return jsonify({"unhash" : hashed_v[0][0]})
    else:
      return jsonify({"unhash" : hashed_a[0][0]})

# this creates the account of user and inserts into database
@application.route('/account', methods=['POST'])
def volunteerInfo():
    connection = sqlite3.connect('sewawebapp.db')
    cursor = connection.cursor()

    if request.method == "POST":

      dataGet = request.get_json()

      username = dataGet[0]['username']
      password = str(dataGet[1]['password'])
      firstname = dataGet[2]['firstname']
      lastname = dataGet[3]['lastname']
      email = dataGet[4]['email']
      chapter = dataGet[5]['chapter']
      birthday = dataGet[6]['birthday']
      eligibility = dataGet[7]['eligibility']
      admin = dataGet[8]['admin']
      adminStatus = "Pending"
      now = datetime.now()
      dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

      salt = "?Sew@!NtErNaT!0NaLh0urS?"
      dataBase_password = password+salt
      hashed = hashlib.md5(dataBase_password.encode())
      hashed_password = hashed.hexdigest()

      if admin == "No":
        duplicate_user = cursor.execute("""SELECT COUNT(volunteerUsername) FROM volunteers WHERE volunteerUsername = ?""", (username,),).fetchall()
        duplicate_user_a = cursor.execute("""SELECT COUNT(adminUsername) FROM admins WHERE adminUsername = ?""", (username,),).fetchall()

        duplicate_email = cursor.execute("""SELECT COUNT(volunteerEmail) FROM volunteers WHERE volunteerEmail = ?""", (email,),).fetchall()
        duplicate_email_a = cursor.execute("""SELECT COUNT(adminEmail) FROM admins WHERE adminEmail = ?""", (email,),).fetchall()

        if duplicate_user == [(1,)] or duplicate_user_a == [(1,)]:
          return jsonify({"duplicate" : "yes"})
        else:
          if duplicate_email == [(1,)] or duplicate_email_a == [(1,)]:
            return jsonify({"email_dup": 'yes'})
          else:
            cursor.execute("""INSERT INTO volunteers(volunteerUsername, volunteerPassword, 
            volunteerFirstName, volunteerLastName, volunteerEmail, volunteerChapter, volunteerBirthday,
            immigrationStatus, createdBy, createdDate, modifiedBy, modifiedDate) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
            username, hashed_password, firstname, lastname, email, chapter, birthday, eligibility, username, dt_string, username, dt_string
            ))

            connection.commit()

            connection.close()
            return jsonify({"nothing" : "no"})
      else:
        duplicate_user = cursor.execute("""SELECT COUNT(adminUsername) FROM admins WHERE adminUsername = ?""", (username,),).fetchall()
        duplicate_user_v = cursor.execute("""SELECT COUNT(volunteerUsername) FROM volunteers WHERE volunteerUsername = ?""", (username,),).fetchall()

        duplicate_email_v = cursor.execute("""SELECT COUNT(volunteerEmail) FROM volunteers WHERE volunteerEmail = ?""", (email,),).fetchall()
        duplicate_email = cursor.execute("""SELECT COUNT(adminEmail) FROM admins WHERE adminEmail = ?""", (email,),).fetchall()

        if duplicate_user == [(1,)] or duplicate_user_v == [(1,)]:
          return jsonify({"duplicate" : "yes"})
        else:
          if duplicate_email == [(1,)] or duplicate_email_v == [(1,)]:
            return jsonify({"email_dup": 'yes'})
          else:
            cursor.execute("""INSERT INTO admins(adminUsername, adminPassword, 
                    adminFirstName, adminLastName, adminEmail, adminChapter, adminStatus, adminBirthday,
                    immigrationStatus, createdBy, createdDate, modifiedBy, modifiedDate) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
                    username, hashed_password, firstname, lastname, email, chapter, adminStatus, birthday, eligibility, username, dt_string, username, dt_string
                    ))

            connection.commit()

            connection.close()
            return jsonify({"nothing" : "no"})

# this checks credentials of user by hashed salt and then admits them or rejects them based on user not found, invalid credentials, rejected, removed, pending
# this also starts the sessiosn for loggedin, admin/volunteer/superadmin
@application.route('/login', methods=['POST'])
def login():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()

    username = dataGet[0]['username']
    password = str(dataGet[1]['password'])

    salt = "?Sew@!NtErNaT!0NaLh0urS?"
    dataBase_password = password+salt
    hashed = hashlib.md5(dataBase_password.encode())
    hashed_password = hashed.hexdigest()

    volunCount = cursor.execute("SELECT COUNT(volunteerUsername) FROM volunteers WHERE volunteerUsername = ?", (username,),).fetchall()
    adminCount = cursor.execute("SELECT COUNT(adminUsername) FROM admins WHERE adminUsername = ?", (username,),).fetchall()
    if volunCount == [(1,)]:
      volunCount2 = cursor.execute("SELECT COUNT(*) FROM volunteers WHERE volunteerUsername = ? AND volunteerPassword= ?", (username, hashed_password,),).fetchall()
      if volunCount2 == [(1,)]:
        session["loggedin"] = True
        session.pop("admin")
        value = {"authenticated" : "volunteer"}
        return jsonify(value)
      else:
        value = {"authenticated" : "No"}
        return jsonify(value)
    elif adminCount == [(1,)]:
      adminCount2 = cursor.execute("SELECT COUNT(*) FROM admins WHERE adminUsername = ? AND adminPassword = ?", (username, hashed_password,),).fetchall()
      adminStatus = cursor.execute("SELECT adminStatus FROM admins WHERE adminUsername = ? AND adminPassword = ?", (username, hashed_password,),).fetchall()

      if adminCount2 == [(1,)]:
        if adminStatus == [("Approved",)]:
          session["loggedin"] = True
          if username == "abantwal":
            session["superadmin"] = True
            session.pop("volunteer")
          value = {"authenticated" : "admin"}
          return jsonify(value)
        elif adminStatus == [("Pending",)]:
          value = {"authenticated" : "Pending"}
          return jsonify(value)
        elif adminStatus == [("Removed",)]:
          value = {"authenticated" : "Removed"}
          return jsonify(value)
        elif adminStatus == [("Rejected",)]:
          value = {"authenticated" : "Rejected"}
          return jsonify(value)
        elif adminStatus == [("Permanently Removed",)]:
          value = {"authenticated" : "Permanently"}
          return jsonify(value)
      else:
        value = {"authenticated" : "No"}
        return jsonify(value)
    else:
      value = {"authenticated" : "No"}
      return jsonify(value)

#this will popualate the text boxes for changing profile admins
@application.route('/populate', methods=['POST'])
def populateProfile():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()
  
  if request.method == "POST":
    dataGet = request.get_json()
    username = dataGet[0]['username']

    adminProfile = cursor.execute("SELECT adminFirstName, adminLastName, adminEmail, adminChapter FROM admins WHERE adminUsername = ?", (username,),).fetchall()

    value = {"fname": adminProfile[0][0], "lname": adminProfile[0][1], "email": adminProfile[0][2], "chapter": adminProfile[0][3]}

    return (jsonify(value))

#this will popualate the text boxes for changing profile admins
@application.route('/populate2', methods=['POST'])
def populateProfile2():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()
  
  if request.method == "POST":
    dataGet = request.get_json()
    username = dataGet[0]['username']

    volunteerProfile = cursor.execute("SELECT volunteerFirstName, volunteerLastName, volunteerEmail, volunteerChapter, volunteerBirthday, immigrationStatus FROM volunteers WHERE volunteerUsername = ?", (username,),).fetchall()

    value = {"fname": volunteerProfile[0][0], "lname": volunteerProfile[0][1], "email": volunteerProfile[0][2], "chapter": volunteerProfile[0][3], "birthday": volunteerProfile[0][4], "immigration": volunteerProfile[0][5]}

    return (jsonify(value))

#this updates the database for a volunteer and if same email is owned by same username, it allows, otherwise errors
@application.route('/volunteerProfile', methods=['POST'])
def profile():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()
  
  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    password = str(dataGet[1]['password'])
    firstname = dataGet[2]['firstname']
    lastname = dataGet[3]['lastname']
    email = dataGet[4]['email']
    chapter = dataGet[5]['chapter']
    birthday = dataGet[6]['birthday']
    eligibility = dataGet[7]['eligibility']
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    salt = "?Sew@!NtErNaT!0NaLh0urS?"
    dataBase_password = password+salt
    hashed = hashlib.md5(dataBase_password.encode())
    hashed_password = hashed.hexdigest()

    duplicate_email = cursor.execute("""SELECT COUNT(volunteerEmail) FROM volunteers WHERE volunteerEmail = ?""", (email,),).fetchall()
    duplicate_email_a = cursor.execute("""SELECT COUNT(adminEmail) FROM admins WHERE adminEmail = ?""", (email,),).fetchall()

    data_email = cursor.execute("SELECT volunteerEmail FROM volunteers WHERE volunteerUsername = ?", (username,),).fetchall()
    data_email_admin = cursor.execute("SELECT adminEmail FROM admins WHERE adminUsername = ?", (username,),).fetchall()

    valid_email = ""

    if data_email == []:
      valid_email = data_email_admin[0][0]
    else:
      valid_email = data_email[0][0]

    if duplicate_email == [(1,)] or duplicate_email_a == [(1,)]:
      if email == valid_email:
        cursor.execute("""UPDATE volunteers SET volunteerPassword = ?, volunteerFirstName  = ?, 
        volunteerLastName = ?, volunteerEmail = ?, volunteerChapter = ?, volunteerBirthday = ?, 
        immigrationStatus = ?, modifiedDate = ? WHERE volunteerUsername = ?""", 
        (hashed_password, firstname, lastname, email, chapter, birthday, eligibility, dt_string, username))

        connection.commit()

        connection.close()
        return jsonify({"success" : "yes"})
      else:
        return jsonify({"email_dup" : "yes"})

    else:
      cursor.execute("""UPDATE volunteers SET volunteerPassword = ?, volunteerFirstName  = ?, 
      volunteerLastName = ?, volunteerEmail = ?, volunteerChapter = ?, volunteerBirthday = ?, 
      immigrationStatus = ?, modifiedDate = ? WHERE volunteerUsername = ?""", 
      (hashed_password, firstname, lastname, email, chapter, birthday, eligibility, dt_string, username))

      connection.commit()

      connection.close()
      return jsonify({"success" : "yes"})

# does the same thing as volunteerProfile but for admins
@application.route('/adminProfile', methods=['POST'])
def admprofile():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    password = str(dataGet[1]['password'])
    firstname = dataGet[2]['firstname']
    lastname = dataGet[3]['lastname']
    email = dataGet[4]['email']
    chapter = dataGet[5]['chapter']
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    salt = "?Sew@!NtErNaT!0NaLh0urS?"
    dataBase_password = password+salt
    hashed = hashlib.md5(dataBase_password.encode())
    hashed_password = hashed.hexdigest()

    duplicate_email_v = cursor.execute("""SELECT COUNT(volunteerEmail) FROM volunteers WHERE volunteerEmail = ?""", (email,),).fetchall()
    duplicate_email = cursor.execute("""SELECT COUNT(adminEmail) FROM admins WHERE adminEmail = ?""", (email,),).fetchall()
    data_email = cursor.execute("SELECT volunteerEmail FROM volunteers WHERE volunteerUsername = ?", (username,),).fetchall()
    data_email_admin = cursor.execute("SELECT adminEmail FROM admins WHERE adminUsername = ?", (username,),).fetchall()

    valid_email = ""

    if data_email == []:
      valid_email = data_email_admin[0][0]
    else:
      valid_email = data_email[0][0]

    if duplicate_email == [(1,)] or duplicate_email_v == [(1,)]:
      if email == valid_email:
        cursor.execute("""UPDATE admins SET adminPassword = ?, adminFirstName  = ?, 
        adminLastName = ?, adminEmail = ?, adminChapter = ?, modifiedDate = ? WHERE adminUsername = ?""", 
        (hashed_password, firstname, lastname, email, chapter, dt_string, username))

        connection.commit()

        connection.close()

        return jsonify({"success": 'yes'})
      else:
        return jsonify({"email_dup" : "yes"})
    else:
      cursor.execute("""UPDATE admins SET adminPassword = ?, adminFirstName  = ?, 
      adminLastName = ?, adminEmail = ?, adminChapter = ?, modifiedDate = ? WHERE adminUsername = ?""", 
      (hashed_password, firstname, lastname, email, chapter, dt_string, username))

      connection.commit()

      connection.close()
      return jsonify({"success" : "yes"})

# this will add an event if the event is not already present in database
@application.route('/add', methods=['POST'])
def addevent():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    eventCat = dataGet[1]['eventcat']
    event = dataGet[2]['event']
    maxhours = dataGet[3]['maxhours']
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    adminChapter = cursor.execute("SELECT adminChapter FROM admins WHERE adminUsername = ?", (username,),).fetchall()

    eventCount = cursor.execute("SELECT COUNT(eventName) FROM events WHERE eventName = ? AND eventStatus = 'Active'", (event,),).fetchall()
    if eventCount == [(1,)]:
        value = {"present": "Yes"}
        return jsonify(value)
    else:
        eventCount = cursor.execute("SELECT COUNT(eventName) FROM events WHERE eventName = ? AND eventStatus = 'Inactive'", (event,),).fetchall()
        if eventCount == [(1,)]:
          id = cursor.execute("SELECT eventCategoryId FROM eventCategory WHERE eventCategoryName = ?", (eventCat,),).fetchall()
          eventCatid = id[0][0]
          cursor.execute("""UPDATE events SET eventCategoryId = ?, eventStatus = 'Active', maxAllowedHours = ? WHERE eventName = ?""", (eventCatid, maxhours, event))
          connection.commit()
          connection.close()
          value = {'present': "successful"}
          return jsonify(value)
        else:
          id = cursor.execute("SELECT eventCategoryId FROM eventCategory WHERE eventCategoryName = ?", (eventCat,),).fetchall()
          eventCatid = id[0][0]
          cursor.execute("""INSERT INTO events(eventCategoryId, eventName, eventStatus, createdBy, createdDate, modifiedBy, 
          modifiedDate, maxAllowedHours, eventChapter) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""", (eventCatid, event, "Active", username, dt_string, username, dt_string, maxhours, adminChapter[0][0]))
          connection.commit()
          connection.close()
          value = {'present': "successful"}
          return jsonify(value)


# this will add an event category if the event is not already present in database
@application.route('/addcat', methods=['POST'])
def addcategory():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    eventCat = dataGet[1]['eventcat']
    maxhours = dataGet[2]['maxhours']
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    adminChapter = cursor.execute("SELECT adminChapter FROM admins WHERE adminUsername = ?", (username,),).fetchall()

    catCount = cursor.execute("SELECT COUNT(eventCategoryName) FROM eventCategory WHERE eventCategoryName = ? AND categoryStatus = 'Active'", (eventCat,),).fetchall()
    if catCount == [(1,)]:
      value = {"present": "Yes"}
      return jsonify(value)
    else:
      catCount = cursor.execute("SELECT COUNT(eventCategoryName) FROM eventCategory WHERE eventCategoryName = ? AND categoryStatus = 'Inactive'", (eventCat,),).fetchall()
      if (catCount == [(1,)]):
        cursor.execute("""UPDATE eventCategory SET categoryStatus = 'Active', maxAllowedHours = ? WHERE eventCategoryName = ?""", (maxhours, eventCat))
        connection.commit()
        connection.close()
        value = {'present': "successful"}
        return jsonify(value)
      else:
        cursor.execute("""INSERT INTO eventCategory(eventCategoryName, maxAllowedHours, categoryStatus, createdBy, createdDate, modifiedBy, 
        modifiedDate, eventCategoryChapter) VALUES(?, ?, ?, ?, ?, ?, ?, ?)""", (eventCat, maxhours, "Active", username, dt_string, username, dt_string, adminChapter[0][0]))
        connection.commit()
        connection.close()
        value = {'present': "successful"}
        return jsonify(value)

#displays the categories in select box of add event screen
@application.route('/getcats', methods=['POST'])
def getcats():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    username = dataGet[0]['username']

    adminChapter = cursor.execute("SELECT adminChapter FROM admins WHERE adminUsername = ?", (username,),).fetchall()

    eventCat = cursor.execute("SELECT eventCategoryName FROM eventCategory WHERE eventCategoryChapter = ? AND categoryStatus = 'Active'", (adminChapter[0][0],),).fetchall()

    information = []

    for i in range(0, len(eventCat)):
      value = {"name" : eventCat[i][0]}
      information.append(value)
    
    return jsonify(information)
    
# this will display all the hours logged from volunteers in a table
@application.route('/page', methods=['POST'])
def title():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']

    information = []

    adminsinfo = cursor.execute("SELECT adminFirstName, adminChapter FROM admins WHERE adminUsername = ?", (username,),).fetchall()

    info = {"firstname": adminsinfo[0][0], "chapter": adminsinfo[0][1]}
    information.append(info)

    loggedHourinfo = cursor.execute("""SELECT volunteerChapter, loggedHourId, 
    volunteerFirstName, volunteerLastName, weekStart, weekEnd, eventName, eventCategoryName, submissionDate, 
    totalHours, submissionStatus, comments FROM loggedHours 
    JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
    JOIN events ON loggedHours.eventNameId = events.eventNameId
    JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
    WHERE submissionStatus = "Approved" OR submissionStatus = "Rejected" OR submissionStatus = "Unapproved"
    ORDER BY submissionStatus DESC, volunteerFirstName ASC, volunteerLastName ASC """,).fetchall()

    for i in range(0, len(loggedHourinfo)):
        volunteerChapter = loggedHourinfo[i][0]
        loggedHourId = loggedHourinfo[i][1]
        volunteerFirstName = loggedHourinfo[i][2]
        volunteerLastName = loggedHourinfo[i][3]
        weekStart = loggedHourinfo[i][4]
        weekEnd = loggedHourinfo[i][5]
        eventName = loggedHourinfo[i][6]
        eventCategoryName = loggedHourinfo[i][7]
        submissionDate = loggedHourinfo[i][8]
        totalHour = loggedHourinfo[i][9]
        submissionStatus = loggedHourinfo[i][10]
        comments = loggedHourinfo[i][11]

        if volunteerChapter == adminsinfo[0][1]:
          name = volunteerFirstName + " " + volunteerLastName
          week = weekStart + "-" + weekEnd

          info2 = {"id": loggedHourId, "name": name, "week": week, "date": submissionDate, "hours": totalHour, "event": eventName, "eventCat": eventCategoryName, "status": submissionStatus, "comments": comments, "weekStart" : weekStart}
          information.append(info2)
          
    return jsonify(information)

# this will populate the certify hour table with all the volunteers and show the unapproved hours yet to be approved before certification
@application.route('/certifyall', methods=['POST'])
def final():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    username = dataGet[0]['username']

    information = []

    adminChapter = cursor.execute("SELECT adminChapter FROM admins WHERE adminUsername = ?", (username,),).fetchall()

    volunteerId = cursor.execute("SELECT volunteerId FROM volunteers").fetchall()

    for i in range(0, len(volunteerId)):
      loggedHourinfo = cursor.execute("""SELECT volunteerChapter, volunteerFirstName, volunteerLastName, totalHours, submissionStatus, volunteers.volunteerId FROM loggedHours 
      JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
      WHERE volunteerChapter = ? AND (submissionStatus = "Approved" OR submissionStatus = "Unapproved") AND loggedHours.volunteerId = ?
      ORDER BY volunteerFirstName ASC, volunteerLastName ASC, volunteerChapter ASC, submissionDate DESC""", (adminChapter[0][0], volunteerId[i][0]),).fetchall()
      totalApproved = 0
      totalUnapproved = 0

      if loggedHourinfo != []:
        for i in range(0, len(loggedHourinfo)):
            volunteerChapter = loggedHourinfo[i][0]
            volunteerFirstName = loggedHourinfo[i][1]
            volunteerLastName = loggedHourinfo[i][2]
            totalHour = loggedHourinfo[i][3]
            submissionStatus = loggedHourinfo[i][4]
            name = volunteerFirstName + " " + volunteerLastName
            if submissionStatus == "Unapproved":
                totalUnapproved += totalHour
            elif submissionStatus == "Approved":
                totalApproved += totalHour

        info2 = {"id": loggedHourinfo[i][5], "name": name, "chapter" : volunteerChapter, "totalhours": totalApproved, "unapproved" : totalUnapproved}
        information.append(info2)

    return jsonify(information)


#this is for looking at all the approved hours from every chapter
@application.route('/approvereport', methods=['POST'])
def approvalReport():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    information = []


    loggedHourinfo = cursor.execute("""SELECT volunteerChapter,
    volunteerFirstName, volunteerLastName, weekStart, weekEnd, eventName, eventCategoryName, submissionDate, 
    totalHours FROM loggedHours 
    JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
    JOIN events ON loggedHours.eventNameId = events.eventNameId
    JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
    WHERE submissionStatus = "Approved"
    ORDER BY volunteerFirstName ASC, volunteerLastName ASC, submissionStatus DESC""",).fetchall()

    if loggedHourinfo != []:
      for i in range(0, len(loggedHourinfo)):
          volunteerChapter = loggedHourinfo[i][0]
          volunteerFirstName = loggedHourinfo[i][1]
          volunteerLastName = loggedHourinfo[i][2]
          weekStart = loggedHourinfo[i][3]
          weekEnd = loggedHourinfo[i][4]
          eventName = loggedHourinfo[i][5]
          eventCategoryName = loggedHourinfo[i][6]
          submissionDate = loggedHourinfo[i][7]
          totalHour = loggedHourinfo[i][8]
          name = volunteerFirstName + " " + volunteerLastName
          week = weekStart + "-" + weekEnd
          info2 = {"name": name, "eventCat": eventCategoryName, "event" : eventName, "chapter" : volunteerChapter, "week" : week, "date" : submissionDate, "totalhours": totalHour}        
          information.append(info2)
    return jsonify(information)

#this is for looking at all the certified hours from every chapter
@application.route('/certifyreport', methods=['POST'])
def certifiedReport():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    information = []


    loggedHourinfo = cursor.execute("""SELECT volunteerChapter,
    volunteerFirstName, volunteerLastName, weekStart, weekEnd, eventName, eventCategoryName, submissionDate, 
    totalHours FROM loggedHours 
    JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
    JOIN events ON loggedHours.eventNameId = events.eventNameId
    JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
    WHERE submissionStatus = "Certified"
    ORDER BY volunteerFirstName ASC, volunteerLastName ASC, submissionStatus DESC""",).fetchall()

    if loggedHourinfo != []:
      for i in range(0, len(loggedHourinfo)):
          volunteerChapter = loggedHourinfo[i][0]
          volunteerFirstName = loggedHourinfo[i][1]
          volunteerLastName = loggedHourinfo[i][2]
          weekStart = loggedHourinfo[i][3]
          weekEnd = loggedHourinfo[i][4]
          eventName = loggedHourinfo[i][5]
          eventCategoryName = loggedHourinfo[i][6]
          submissionDate = loggedHourinfo[i][7]
          totalHour = loggedHourinfo[i][8]
          name = volunteerFirstName + " " + volunteerLastName
          week = weekStart + "-" + weekEnd
          info2 = {"name": name, "eventCat": eventCategoryName, "event" : eventName, "chapter" : volunteerChapter, "week" : week, "date" : submissionDate, "totalhours": totalHour}        
          information.append(info2)
    return jsonify(information)


#this is for looking at all the rejected hours from every chapter
@application.route('/rejectreport', methods=['POST'])
def rejectedReport():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    information = []


    loggedHourinfo = cursor.execute("""SELECT volunteerChapter,
    volunteerFirstName, volunteerLastName, weekStart, weekEnd, eventName, eventCategoryName, submissionDate, 
    totalHours FROM loggedHours 
    JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
    JOIN events ON loggedHours.eventNameId = events.eventNameId
    JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
    WHERE submissionStatus = "Rejected"
    ORDER BY volunteerFirstName ASC, volunteerLastName ASC, submissionStatus DESC""",).fetchall()

    if loggedHourinfo != []:
      for i in range(0, len(loggedHourinfo)):
          volunteerChapter = loggedHourinfo[i][0]
          volunteerFirstName = loggedHourinfo[i][1]
          volunteerLastName = loggedHourinfo[i][2]
          weekStart = loggedHourinfo[i][3]
          weekEnd = loggedHourinfo[i][4]
          eventName = loggedHourinfo[i][5]
          eventCategoryName = loggedHourinfo[i][6]
          submissionDate = loggedHourinfo[i][7]
          totalHour = loggedHourinfo[i][8]
          name = volunteerFirstName + " " + volunteerLastName
          week = weekStart + "-" + weekEnd
          info2 = {"name": name, "eventCat": eventCategoryName, "event" : eventName, "chapter" : volunteerChapter, "week" : week, "date" : submissionDate, "totalhours": totalHour}        
          information.append(info2)
    return jsonify(information)

#this is for looking at all the unapproved hours from every chapter
@application.route('/unapprovedreport', methods=['POST'])
def unapprovedReport():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    information = []


    loggedHourinfo = cursor.execute("""SELECT volunteerChapter,
    volunteerFirstName, volunteerLastName, weekStart, weekEnd, eventName, eventCategoryName, submissionDate, 
    totalHours FROM loggedHours 
    JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
    JOIN events ON loggedHours.eventNameId = events.eventNameId
    JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
    WHERE submissionStatus = "Unapproved"
    ORDER BY volunteerFirstName ASC, volunteerLastName ASC, submissionStatus DESC""",).fetchall()

    if loggedHourinfo != []:
      for i in range(0, len(loggedHourinfo)):
          volunteerChapter = loggedHourinfo[i][0]
          volunteerFirstName = loggedHourinfo[i][1]
          volunteerLastName = loggedHourinfo[i][2]
          weekStart = loggedHourinfo[i][3]
          weekEnd = loggedHourinfo[i][4]
          eventName = loggedHourinfo[i][5]
          eventCategoryName = loggedHourinfo[i][6]
          submissionDate = loggedHourinfo[i][7]
          totalHour = loggedHourinfo[i][8]
          name = volunteerFirstName + " " + volunteerLastName
          week = weekStart + "-" + weekEnd
          info2 = {"name": name, "eventCat": eventCategoryName, "event" : eventName, "chapter" : volunteerChapter, "week" : week, "date" : submissionDate, "totalhours": totalHour}        
          information.append(info2)
    return jsonify(information)

#this is for looking at approved hours and validating medals
@application.route('/medals', methods=['POST'])
def medalReport():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    information = []
    medal_status = ""
    todays_date = date.today()
    year = todays_date.year

    volunteerId = cursor.execute("SELECT volunteerId FROM volunteers").fetchall()

    for i in range(0, len(volunteerId)):
      loggedHourinfo = cursor.execute("""SELECT volunteerChapter, loggedHourId, 
      volunteerFirstName, volunteerLastName, totalHours, submissionStatus, volunteerBirthday, volunteers.volunteerId FROM loggedHours 
      JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
      WHERE (submissionStatus = "Certified" OR submissionStatus = "Unapproved") AND immigrationStatus = "US Citizen or Greencard Holder" AND loggedHours.volunteerId = ?
      ORDER BY volunteerFirstName ASC, volunteerLastName ASC, volunteerChapter ASC, submissionDate DESC""", (volunteerId[i][0],),).fetchall()
      totalApproved = 0
      totalUnapproved = 0

      if loggedHourinfo != []:
        for i in range(0, len(loggedHourinfo)):
          volunteerChapter = loggedHourinfo[i][0]
          volunteerFirstName = loggedHourinfo[i][2]
          volunteerLastName = loggedHourinfo[i][3]
          totalHour = loggedHourinfo[i][4]
          submissionStatus = loggedHourinfo[i][5]
          name = volunteerFirstName + " " + volunteerLastName
          if submissionStatus == "Unapproved":
            totalUnapproved += totalHour
          elif submissionStatus == "Certified":
            totalApproved += totalHour

        volunteerBirthday = str(loggedHourinfo[i][6])
        tokens = volunteerBirthday.split("-")
        age = year - int(tokens[0])
        if age >= 5:
          if totalApproved >= 26:
            medal_status = "Bronze"
          elif totalApproved >= 50:
            medal_status = "Silver"
          elif totalApproved >= 75:
            medal_status = "Gold"
          else:
            medal_status = "N/A"
        elif age >= 11:
          if totalApproved >= 50:
            medal_status = "Bronze"
          elif totalApproved >= 74:
            medal_status = "Silver"
          elif totalApproved >= 100:
            medal_status = "Gold"
          else:
            medal_status = "N/A"
        elif age >= 16:
          if totalApproved >= 100:
            medal_status = "Bronze"
          elif totalApproved >= 175:
            medal_status = "Silver"
          elif totalApproved >= 250:
            medal_status = "Gold"
          else:
            medal_status = "N/A"
        elif age >= 26:
            if totalApproved >= 100:
              medal_status = "Bronze"
            elif totalApproved >= 250:
              medal_status = "Silver"
            elif totalApproved >= 500:
              medal_status = "Gold"
            else:
              medal_status = "N/A"
        else:
          medal_status = "N/A"

        info2 = {"id": loggedHourinfo[i][7], "name": name, "chapter" : volunteerChapter, "totalhours": totalApproved, "unapproved" : totalUnapproved, "medal" : medal_status}
        information.append(info2)
    return jsonify(information)

# this is the action of updating the database when an admin approves, rejects or certify
@application.route('/validate', methods=['POST'])
def validate():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    action = dataGet[1]["action"]
    comments = dataGet[2]["comment"]
    id = dataGet[3]["loggedHourId"]
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    adminId = cursor.execute("SELECT adminId FROM admins WHERE adminUsername = ?", (username,),).fetchall()
    numOfVal = cursor.execute("SELECT numOfValidation FROM loggedHours WHERE loggedHourId = ?", (id,),).fetchall()
    comment = cursor.execute("SELECT comments FROM loggedHours WHERE loggedHourId = ?", (id,),).fetchall()
    adminUsername = cursor.execute("SELECT modifiedBy FROM loggedHours WHERE loggedHourId = ?", (id,),).fetchall()
    firstValidation = cursor.execute("SELECT firstValidation FROM loggedHours WHERE loggedHourId = ?", (id,),).fetchall()

    if numOfVal[0][0] == 0 and comment[0][0] != "" and comments == "":
      cursor.execute("""UPDATE loggedHours SET adminId = ?, numOfValidation = ?, firstValidation = ?, modifiedBy = ?, modifiedDate = ?, firstValidation = ? WHERE loggedHourId = ?""", (adminId[0][0], 1, action, username, dt_string, action, id))
      connection.commit()
      connection.close()
      return jsonify({"same": "one"})
    elif numOfVal[0][0] == 0:
      cursor.execute("""UPDATE loggedHours SET adminId = ?, numOfValidation = ?, firstValidation = ?, comments = ?, modifiedBy = ?, modifiedDate = ?, firstValidation = ? WHERE loggedHourId = ?""", (adminId[0][0], 1, action, comments, username, dt_string, action, id))
      connection.commit()
      connection.close()
      return jsonify({"same": "one"})
    elif numOfVal[0][0] == 1 and adminUsername[0][0] != username and comment[0][0] != "" and comments == "" and firstValidation[0][0] == action:
      cursor.execute("""UPDATE loggedHours SET adminId = ?, numOfValidation = ?, submissionStatus = ?, modifiedBy = ?, modifiedDate = ?, firstValidation = ? WHERE loggedHourId = ?""", (adminId[0][0], 2, action, username, dt_string, action, id))
      connection.commit()
      connection.close()
    elif numOfVal[0][0] == 1 and adminUsername[0][0] != username and firstValidation[0][0] == action:
      cursor.execute("""UPDATE loggedHours SET adminId = ?, numOfValidation = ?, submissionStatus = ?, comments = ?, modifiedBy = ?, modifiedDate = ?, firstValidation = ? WHERE loggedHourId = ?""", (adminId[0][0], 2, action, comments, username, dt_string, action, id))
      connection.commit()
      connection.close()
    elif numOfVal[0][0] == 1 and adminUsername[0][0] == username and comment[0][0] != "" and comments == "" and firstValidation[0][0] != action:
      cursor.execute("""UPDATE loggedHours SET adminId = ?, numOfValidation = ?, modifiedBy = ?, modifiedDate = ?, firstValidation = ? WHERE loggedHourId = ?""", (adminId[0][0], 1, username, dt_string, action, id))
      connection.commit()
      connection.close()
      return jsonify({"same": "one"})
    elif numOfVal[0][0] == 1 and adminUsername[0][0] == username and firstValidation[0][0] != action:
      cursor.execute("""UPDATE loggedHours SET adminId = ?, numOfValidation = ?, comments = ?, modifiedBy = ?, modifiedDate = ?, firstValidation = ? WHERE loggedHourId = ?""", (adminId[0][0], 1, comments, username, dt_string, action, id))
      connection.commit()
      connection.close()
      return jsonify({"same": "one"})
    elif numOfVal[0][0] == 1 and adminUsername[0][0] != username and firstValidation[0][0] != action:
      return jsonify({"same": "diff"})
    elif numOfVal[0][0] == 2 and comment[0][0] != "" and comments == "":
      cursor.execute("""UPDATE loggedHours SET adminId = ?, numOfValidation = ?, submissionStatus = ?, modifiedBy = ?, modifiedDate = ?, firstValidation = ? WHERE loggedHourId = ?""", (adminId[0][0], 2, action, username, dt_string, action, id))
      connection.commit()
      connection.close()
    elif numOfVal[0][0] == 2:
      cursor.execute("""UPDATE loggedHours SET adminId = ?, numOfValidation = ?, submissionStatus = ?, comments = ?, modifiedBy = ?, modifiedDate = ?, firstValidation = ? WHERE loggedHourId = ?""", (adminId[0][0], 2, action, comments, username, dt_string, action, id))
      connection.commit()
      connection.close()
    else:
      return jsonify({"same": "yes"})

    return jsonify({"same": "two"})


# this will filter the approved table showing the records
@application.route('/filterapproved', methods=['POST'])
def filtera():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    dates = dataGet[0]["date"]
    dates2 = dataGet[1]["dates"]
    chapter = dataGet[2]["chapter"]

    information = []

    if chapter == "All Chapters":
      records = cursor.execute("""SELECT volunteerFirstName, volunteerLastName, eventCategoryName, eventName, volunteerChapter, weekStart, weekEnd, submissionDate, totalHours FROM loggedHours 
    JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
    JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
    JOIN events ON loggedHours.eventNameId = events.eventNameId
    WHERE submissionStatus = "Approved" AND submissionDate BETWEEN ? AND ?
    ORDER BY volunteerFirstName ASC, volunteerLastName ASC, submissionDate ASC""", (dates, dates2,),).fetchall()
    else:
      records = cursor.execute("""SELECT volunteerFirstName, volunteerLastName, eventCategoryName, eventName, volunteerChapter, weekStart, weekEnd, submissionDate, totalHours FROM loggedHours 
      JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
      JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
      JOIN events ON loggedHours.eventNameId = events.eventNameId
      WHERE volunteerChapter = ? AND submissionStatus = "Approved" AND submissionDate BETWEEN ? AND ?
      ORDER BY volunteerFirstName ASC, volunteerLastName ASC, submissionDate ASC""", (chapter, dates, dates2,),).fetchall()


    for i in range(0, len(records)):
      volunteerFirstName = records[i][0]
      volunteerLastName = records[i][1]
      eventCategoryName = records[i][2]
      eventName = records[i][3]
      volunteerChapter = records[i][4]
      weekStart = records[i][5]
      weekEnd = records[i][6]
      submissionDate = records[i][7]
      totalHour = records[i][8]
      name = volunteerFirstName + " " + volunteerLastName
      week = weekStart + "-" + weekEnd
      info2 = {"name": name, "eventCat": eventCategoryName, "event" : eventName, "chapter" : volunteerChapter, "week" : week, "date" : submissionDate, "totalhours": totalHour}        
      information.append(info2)

    return jsonify(information)

# this will filter the certified table showing the records
@application.route('/filtercertified', methods=['POST'])
def filterc():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    dates = dataGet[0]["date"]
    dates2 = dataGet[1]["dates"]
    chapter = dataGet[2]["chapter"]

    information = []

    if chapter == "All Chapters":
      records = cursor.execute("""SELECT volunteerFirstName, volunteerLastName, eventCategoryName, eventName, volunteerChapter, weekStart, weekEnd, submissionDate, totalHours FROM loggedHours 
    JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
    JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
    JOIN events ON loggedHours.eventNameId = events.eventNameId
    WHERE submissionStatus = "Certified" AND submissionDate BETWEEN ? AND ?
    ORDER BY volunteerFirstName ASC, volunteerLastName ASC, submissionDate ASC""", (dates, dates2,),).fetchall()
    else:
      records = cursor.execute("""SELECT volunteerFirstName, volunteerLastName, eventCategoryName, eventName, volunteerChapter, weekStart, weekEnd, submissionDate, totalHours FROM loggedHours 
      JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
      JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
      JOIN events ON loggedHours.eventNameId = events.eventNameId
      WHERE volunteerChapter = ? AND submissionStatus = "Certified" AND submissionDate BETWEEN ? AND ?
      ORDER BY volunteerFirstName ASC, volunteerLastName ASC, submissionDate ASC""", (chapter, dates, dates2,),).fetchall()


    for i in range(0, len(records)):
      volunteerFirstName = records[i][0]
      volunteerLastName = records[i][1]
      eventCategoryName = records[i][2]
      eventName = records[i][3]
      volunteerChapter = records[i][4]
      weekStart = records[i][5]
      weekEnd = records[i][6]
      submissionDate = records[i][7]
      totalHour = records[i][8]
      name = volunteerFirstName + " " + volunteerLastName
      week = weekStart + "-" + weekEnd
      info2 = {"name": name, "eventCat": eventCategoryName, "event" : eventName, "chapter" : volunteerChapter, "week" : week, "date" : submissionDate, "totalhours": totalHour}        
      information.append(info2)

    return jsonify(information)

# this will filter the rejected table showing the records
@application.route('/filterrejected', methods=['POST'])
def filterr():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    dates = dataGet[0]["date"]
    dates2 = dataGet[1]["dates"]
    chapter = dataGet[2]["chapter"]

    information = []

    if chapter == "All Chapters":
      records = cursor.execute("""SELECT volunteerFirstName, volunteerLastName, eventCategoryName, eventName, volunteerChapter, weekStart, weekEnd, submissionDate, totalHours FROM loggedHours 
    JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
    JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
    JOIN events ON loggedHours.eventNameId = events.eventNameId
    WHERE submissionStatus = "Rejected" AND submissionDate BETWEEN ? AND ?
    ORDER BY volunteerFirstName ASC, volunteerLastName ASC, submissionDate ASC""", (dates, dates2,),).fetchall()
    else:
      records = cursor.execute("""SELECT volunteerFirstName, volunteerLastName, eventCategoryName, eventName, volunteerChapter, weekStart, weekEnd, submissionDate, totalHours FROM loggedHours 
      JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
      JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
      JOIN events ON loggedHours.eventNameId = events.eventNameId
      WHERE volunteerChapter = ? AND submissionStatus = "Rejected" AND submissionDate BETWEEN ? AND ?
      ORDER BY volunteerFirstName ASC, volunteerLastName ASC, submissionDate ASC""", (chapter, dates, dates2,),).fetchall()


    for i in range(0, len(records)):
      volunteerFirstName = records[i][0]
      volunteerLastName = records[i][1]
      eventCategoryName = records[i][2]
      eventName = records[i][3]
      volunteerChapter = records[i][4]
      weekStart = records[i][5]
      weekEnd = records[i][6]
      submissionDate = records[i][7]
      totalHour = records[i][8]
      name = volunteerFirstName + " " + volunteerLastName
      week = weekStart + "-" + weekEnd
      info2 = {"name": name, "eventCat": eventCategoryName, "event" : eventName, "chapter" : volunteerChapter, "week" : week, "date" : submissionDate, "totalhours": totalHour}        
      information.append(info2)

    return jsonify(information)

# this will filter the unapproved table showing the records
@application.route('/filterunapproved', methods=['POST'])
def filteru():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    dates = dataGet[0]["date"]
    dates2 = dataGet[1]["dates"]
    chapter = dataGet[2]["chapter"]

    information = []

    if chapter == "All Chapters":
      records = cursor.execute("""SELECT volunteerFirstName, volunteerLastName, eventCategoryName, eventName, volunteerChapter, weekStart, weekEnd, submissionDate, totalHours FROM loggedHours 
    JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
    JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
    JOIN events ON loggedHours.eventNameId = events.eventNameId
    WHERE submissionStatus = "Unapproved" AND submissionDate BETWEEN ? AND ?
    ORDER BY volunteerFirstName ASC, volunteerLastName ASC, submissionDate ASC""", (dates, dates2,),).fetchall()
    else:
      records = cursor.execute("""SELECT volunteerFirstName, volunteerLastName, eventCategoryName, eventName, volunteerChapter, weekStart, weekEnd, submissionDate, totalHours FROM loggedHours 
      JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
      JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
      JOIN events ON loggedHours.eventNameId = events.eventNameId
      WHERE volunteerChapter = ? AND submissionStatus = "Unapproved" AND submissionDate BETWEEN ? AND ?
      ORDER BY volunteerFirstName ASC, volunteerLastName ASC, submissionDate ASC""", (chapter, dates, dates2,),).fetchall()

    for i in range(0, len(records)):
      volunteerFirstName = records[i][0]
      volunteerLastName = records[i][1]
      eventCategoryName = records[i][2]
      eventName = records[i][3]
      volunteerChapter = records[i][4]
      weekStart = records[i][5]
      weekEnd = records[i][6]
      submissionDate = records[i][7]
      totalHour = records[i][8]
      name = volunteerFirstName + " " + volunteerLastName
      week = weekStart + "-" + weekEnd
      info2 = {"name": name, "eventCat": eventCategoryName, "event" : eventName, "chapter" : volunteerChapter, "week" : week, "date" : submissionDate, "totalhours": totalHour}        
      information.append(info2)

    return jsonify(information)

# this will filter the year end report table showing the records
@application.route('/filtermedals', methods=['POST'])
def filterm():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    selectedyear = dataGet[0]["year"]
    chapter = dataGet[1]["chapter"]

    information = []
    medal_status = ""
    todays_date = date.today()
    year = todays_date.year

    between1 = selectedyear + "-01-01"
    between2 = selectedyear + "-12-31"

    volunteerId = cursor.execute("SELECT volunteerId FROM volunteers").fetchall()

    for i in range(0, len(volunteerId)):
      if chapter == "All Chapters":
        loggedHourinfo = cursor.execute("""SELECT volunteerChapter, loggedHourId, 
        volunteerFirstName, volunteerLastName, totalHours, submissionStatus, volunteerBirthday, volunteers.volunteerId FROM loggedHours 
        JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
        WHERE (submissionStatus = "Certified" OR submissionStatus = "Unapproved") AND loggedHours.volunteerId = ? AND immigrationStatus = "US Citizen or Greencard Holder" AND submissionDate BETWEEN ? AND ?
        ORDER BY volunteerFirstName ASC, volunteerLastName ASC, volunteerChapter ASC, submissionDate DESC""", (volunteerId[i][0], between1, between2)).fetchall()
      else:
        loggedHourinfo = cursor.execute("""SELECT volunteerChapter, loggedHourId, 
        volunteerFirstName, volunteerLastName, totalHours, submissionStatus, volunteerBirthday, volunteers.volunteerId FROM loggedHours 
        JOIN volunteers ON loggedHours.volunteerId = volunteers.volunteerId
        WHERE volunteerChapter = ? AND (submissionStatus = "Certified" OR submissionStatus = "Unapproved") AND loggedHours.volunteerId = ? AND immigrationStatus = "US Citizen or Greencard Holder" AND submissionDate BETWEEN ? AND ?
        ORDER BY volunteerFirstName ASC, volunteerLastName ASC, volunteerChapter ASC, submissionDate DESC""", (chapter, volunteerId[i][0], between1, between2)).fetchall()
      totalApproved = 0
      totalUnapproved = 0

      if loggedHourinfo != []:
        for i in range(0, len(loggedHourinfo)):
          volunteerChapter = loggedHourinfo[i][0]
          volunteerFirstName = loggedHourinfo[i][2]
          volunteerLastName = loggedHourinfo[i][3]
          totalHour = loggedHourinfo[i][4]
          submissionStatus = loggedHourinfo[i][5]
          name = volunteerFirstName + " " + volunteerLastName
          if submissionStatus == "Unapproved":
            totalUnapproved += totalHour
          elif submissionStatus == "Certified":
            totalApproved += totalHour

        volunteerBirthday = str(loggedHourinfo[i][6])
        tokens = volunteerBirthday.split("-")
        age = year - int(tokens[0])
        if age >= 5:
          if totalApproved >= 26:
            medal_status = "Bronze"
          elif totalApproved >= 50:
            medal_status = "Silver"
          elif totalApproved >= 75:
            medal_status = "Gold"
          else:
            medal_status = "N/A"
        elif age >= 11:
          if totalApproved >= 50:
            medal_status = "Bronze"
          elif totalApproved >= 74:
            medal_status = "Silver"
          elif totalApproved >= 100:
            medal_status = "Gold"
          else:
            medal_status = "N/A"
        elif age >= 16:
          if totalApproved >= 100:
            medal_status = "Bronze"
          elif totalApproved >= 175:
            medal_status = "Silver"
          elif totalApproved >= 250:
            medal_status = "Gold"
          else:
            medal_status = "N/A"
        elif age >= 26:
            if totalApproved >= 100:
              medal_status = "Bronze"
            elif totalApproved >= 250:
              medal_status = "Silver"
            elif totalApproved >= 500:
              medal_status = "Gold"
            else:
              medal_status = "N/A"
        else:
          medal_status = "N/A"

        info2 = {"id": loggedHourinfo[i][7], "name": name, "chapter" : volunteerChapter, "totalhours": totalApproved, "unapproved" : totalUnapproved, "medal" : medal_status}
        information.append(info2)
    return jsonify(information)


#invalidates any diabled radio button due to incorrect year
@application.route('/invalid', methods=['POST'])
def invalidate():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
 
    dataGet = request.get_json()
    id = dataGet[0]['id']

    cursor.execute("""UPDATE loggedHours SET submissionStatus = "Invalid" WHERE loggedHourId = ?""", (id,))
    connection.commit()
    connection.close

    return jsonify()

#this will certify all the hours at once and throw error if a hour is unapproved
@application.route('/done', methods=['POST'])
def done():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    action = dataGet[1]["action"]
    id = dataGet[2]["Id"]
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    adminId = cursor.execute("SELECT adminId FROM admins WHERE adminUsername = ?", (username,),).fetchall()

    cursor.execute("""UPDATE loggedHours SET adminId = ?, submissionStatus = ?, modifiedBy = ?, modifiedDate = ? WHERE volunteerId = ? AND submissionStatus = "Approved" """, (adminId[0][0], action, username, dt_string, id))
    connection.commit()
    cursor.execute("""UPDATE loggedHours SET adminId = ?, submissionStatus = ?, modifiedBy = ?, modifiedDate = ? WHERE volunteerId = ? AND submissionStatus = "Rejected" """, (adminId[0][0], "Discarded", username, dt_string, id))
    connection.commit()

    connection.close()

    return jsonify({})

#this will approve all records that are unapproved in validation page
@application.route('/approveall', methods=['POST'])
def approveAll():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    adminId = cursor.execute("SELECT adminId FROM admins WHERE adminUsername = ?", (username,),).fetchall()
    adminChapter = cursor.execute("SELECT adminChapter FROM admins WHERE adminUsername = ?", (username,),).fetchall()
    volunteerIds = cursor.execute("SELECT volunteerId FROM volunteers WHERE volunteerChapter = ?", (adminChapter[0][0],),).fetchall()
    unapproved_records = cursor.execute("SELECT volunteerId FROM loggedHours WHERE submissionStatus = 'Unapproved'",).fetchall()
    numOfVal = cursor.execute("SELECT numOfValidation FROM loggedHours",).fetchall()
    adminUsername = cursor.execute("SELECT modifiedBy FROM loggedHours",).fetchall()
    needAnother = True
    needAnother2 = True

    for check1 in range(0, len(adminUsername)):
      if adminUsername[check1][0] != username:
        needAnother = False
      else:
        needAnother = True
        break
    
    for check2 in range(0, len(numOfVal)):
      if numOfVal[check2][0] == 1 or numOfVal[check2][0] == 2:
        needAnother2 = False
      else:
        needAnother2 = True
        break
    
    if needAnother == False and needAnother2 == False:
      for i in range(0, len(volunteerIds)):
        for j in range(0, len(unapproved_records)):
          if unapproved_records[j][0] == volunteerIds[i][0]:
            cursor.execute("UPDATE loggedHours SET adminId = ?, numOfValidation = ?, submissionStatus = 'Approved', modifiedBy = ?, modifiedDate = ? WHERE submissionStatus = 'Unapproved' AND volunteerId = ? AND firstValidation = 'Approved'", (adminId[0][0], 2, username, dt_string, unapproved_records[0][0]))
            connection.commit()

      connection.close()
      return jsonify({"approveall": "yes"})
    else:
      return jsonify({"approveall": "no"})


#this will reject all records that are unapproved in validation page
@application.route('/rejectall', methods=['POST'])
def rejectAll():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    adminId = cursor.execute("SELECT adminId FROM admins WHERE adminUsername = ?", (username,),).fetchall()
    adminChapter = cursor.execute("SELECT adminChapter FROM admins WHERE adminUsername = ?", (username,),).fetchall()
    volunteerIds = cursor.execute("SELECT volunteerId FROM volunteers WHERE volunteerChapter = ?", (adminChapter[0][0],),).fetchall()
    unapproved_records = cursor.execute("SELECT volunteerId FROM loggedHours WHERE submissionStatus = 'Unapproved'",).fetchall()
    numOfVal = cursor.execute("SELECT numOfValidation FROM loggedHours",).fetchall()
    adminUsername = cursor.execute("SELECT modifiedBy FROM loggedHours",).fetchall()
    needAnother = True
    needAnother2 = True

    for check1 in range(0, len(adminUsername)):
      if adminUsername[check1][0] != username:
        needAnother = False
      else:
        needAnother = True
        break
    
    for check2 in range(0, len(numOfVal)):
      if numOfVal[check2][0] == 1 or numOfVal[check2][0] == 2:
        needAnother2 = False
      else:
        needAnother2 = True
        break

    if needAnother == False and needAnother2 == False:
      for i in range(0, len(volunteerIds)):
        for j in range(0, len(unapproved_records)):
          if unapproved_records[j][0] == volunteerIds[i][0]:
            cursor.execute("UPDATE loggedHours SET adminId = ?, numOfValidation = ?, submissionStatus = 'Rejected', modifiedBy = ?, modifiedDate = ? WHERE submissionStatus = 'Unapproved' AND volunteerId = ? AND firstValidation = 'Rejected'", (adminId[0][0], 2, username, dt_string, unapproved_records[0][0]))
            connection.commit()
      connection.close()
      return jsonify({"rejectall": "yes"})
    else:
      return jsonify({"rejectall": "no"})

# remove an event which updates the database to inactive
@application.route('/remove', methods=['POST'])
def remove():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    username = dataGet[0]['username']

    information = []

    adminChapter = cursor.execute("SELECT adminChapter FROM admins WHERE adminUsername = ?", (username,),).fetchall()

    event = cursor.execute("""SELECT eventNameId, eventName, eventCategoryName, eventStatus FROM events 
    JOIN eventCategory ON events.eventCategoryId = eventCategory.eventCategoryId
    WHERE eventChapter = ?""", (adminChapter[0][0],),).fetchall()

    for i in range(0, len(event)):
      if (event[i][3] == "Active"):
        events = event[i][1]
        eventCategory = event[i][2]
        eventId = event[i][0]

        info = {"id": eventId, "event" : events, "eventCat": eventCategory}
        information.append(info)

  return jsonify(information)

# remove an event which updates the database to inactive
@application.route('/removecat', methods=['POST'])
def removeCat():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    username = dataGet[0]['username']
    information = []

    adminChapter = cursor.execute("SELECT adminChapter FROM admins WHERE adminUsername = ?", (username,),).fetchall()

    eventCat = cursor.execute("""SELECT eventCategoryId, eventCategoryName, categoryStatus FROM eventCategory WHERE eventCategoryChapter = ?""", (adminChapter[0][0],),).fetchall()

    for i in range(0, len(eventCat)):
      if (eventCat[i][2] == "Active"):
        eventCatName = eventCat[i][1]
        eventCatId = eventCat[i][0]

        info = {"id": eventCatId, "eventCat": eventCatName}
        information.append(info)

  return jsonify(information)

#this checks to display only active event category in remove events screen
@application.route('/check', methods=['POST'])
def checkEvent():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    id = dataGet[1]['id']
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    cursor.execute("""UPDATE events SET eventStatus = ?, modifiedBy = ?, modifiedDate = ? WHERE eventNameId = ?""", ("Inactive", username, dt_string, id))

    connection.commit()

    connection.close()

    return jsonify({})

#this checks to display only active event categories in remove events screen
@application.route('/checkcat', methods=['POST'])
def checkCategory():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    id = dataGet[1]['id']
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    cursor.execute("""UPDATE eventCategory SET categoryStatus = ?, modifiedBy = ?, modifiedDate = ? WHERE eventCategoryId = ?""", ("Inactive", username, dt_string, id))

    connection.commit()

    connection.close()

    return jsonify({})

# show appproved or pending admins in the tables 
@application.route('/approveadmin', methods=['POST'])
def approve():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']

    information = []

    if username != "abantwal":
      adminChapter = cursor.execute("SELECT adminChapter FROM admins WHERE adminUsername = ?", (username,),).fetchall()
      adminInfo = cursor.execute("SELECT adminId, adminFirstName, adminLastName, adminStatus, adminUsername FROM admins WHERE adminChapter = ?", (adminChapter[0][0],),).fetchall()

      for i in range(0, len(adminInfo)):
        if (adminInfo[i][4] != "abantwal" and adminInfo[i][3] == "Approved" or adminInfo[i][3] == "Pending"):
          id = adminInfo[i][0]
          name = adminInfo[i][1] + " " + adminInfo[i][2]
          status = adminInfo[i][3]

          info = {"id" : id, "name" : name, "status" : status}
          information.append(info)
    else:
      adminInfo = cursor.execute("SELECT adminId, adminFirstName, adminLastName, adminStatus, adminChapter FROM admins",).fetchall()

      for i in range(0, len(adminInfo)):
        if (adminInfo[i][3] == "Approved" or adminInfo[i][3] == "Pending"):
          id = adminInfo[i][0]
          name = adminInfo[i][1] + " " + adminInfo[i][2] + "_" + adminInfo[i][4]
          status = adminInfo[i][3]

          info = {"id" : id, "name" : name, "status" : status}
          information.append(info)

    return jsonify(information)

# show appproved or pending admins in the tables 
@application.route('/reinstate', methods=['POST'])
def approveagain():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']

    information = []

    if username != "abantwal":
      adminChapter = cursor.execute("SELECT adminChapter FROM admins WHERE adminUsername = ?", (username,),).fetchall()
      adminInfo = cursor.execute("SELECT adminId, adminFirstName, adminLastName, adminStatus FROM admins WHERE adminChapter = ?", (adminChapter[0][0],),).fetchall()

      for i in range(0, len(adminInfo)):
        if (adminInfo[i][3] == "Removed" or adminInfo[i][3] == "Rejected"):
          id = adminInfo[i][0]
          name = adminInfo[i][1] + " " + adminInfo[i][2]
          status = adminInfo[i][3]

          info = {"id" : id, "name" : name, "status" : status}
          information.append(info)
    else:
      adminInfo = cursor.execute("SELECT adminId, adminFirstName, adminLastName, adminStatus FROM admins",).fetchall()

      for i in range(0, len(adminInfo)):
        if (adminInfo[i][3] == "Removed" or adminInfo[i][3] == "Rejected"):
          id = adminInfo[i][0]
          name = adminInfo[i][1] + " " + adminInfo[i][2]
          status = adminInfo[i][3]

          info = {"id" : id, "name" : name, "status" : status}
          information.append(info)

    return jsonify(information)

# approve an admin
@application.route('/approved', methods=['POST'])
def approved():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    id = dataGet[1]["id"]
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    cursor.execute("""UPDATE admins SET adminStatus = ?, modifiedBy = ?, modifiedDate = ? WHERE adminId = ?""", ("Approved", username, dt_string, id))

    connection.commit()

    connection.close()

    return jsonify({})

#reject an admin
@application.route('/rejected', methods=['POST'])
def rejected():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    id = dataGet[1]["id"]
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    cursor.execute("""UPDATE admins SET adminStatus = ?, modifiedBy = ?, modifiedDate = ? WHERE adminId = ?""", ("Rejected", username, dt_string, id))

    connection.commit()

    connection.close()

    return jsonify({})

#remove an admin
@application.route('/removed', methods=['POST'])
def removed():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    id = dataGet[1]["id"]
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    value = {}

    adminUsername = cursor.execute("SELECT adminUsername FROM admins WHERE adminId = ?", (id,),).fetchall()

    if adminUsername[0][0] == username:
      cursor.execute("""UPDATE admins SET adminStatus = ?, modifiedBy = ?, modifiedDate = ? WHERE adminId = ?""", ("Removed", username, dt_string, id))
      connection.commit()
      connection.close()
      value = {"selfremove" : "True"}
    else:
      cursor.execute("""UPDATE admins SET adminStatus = ?, modifiedBy = ?, modifiedDate = ? WHERE adminId = ?""", ("Removed", username, dt_string, id))
      connection.commit()
      connection.close()
      value = {"selfremove" : "False"}

    return jsonify(value)

@application.route('/permanent', methods=['POST'])
def removedPermanently():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]['username']
    id = dataGet[1]["id"]
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    cursor.execute("""UPDATE admins SET adminStatus = ?, modifiedBy = ?, modifiedDate = ? WHERE adminId = ?""", ("Permanently Removed", username, dt_string, id))
    connection.commit()
    connection.close()

    return jsonify({})

#get the code in the database after email is sent
@application.route('/getcode', methods=['POST'])
def getcode():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    email = dataGet[0]['email']
    code = str(dataGet[1]["code"])

    salt = "v$rr!YP@ssw0rD?"
    dataBase_password = code+salt
    hashed = hashlib.md5(dataBase_password.encode())
    hashed_code = hashed.hexdigest()

    information = []

    adminemail = cursor.execute("SELECT adminEmail FROM admins WHERE adminEmail = ?", (email,),).fetchall()
    volunteeremail = cursor.execute("SELECT volunteerEmail FROM volunteers WHERE volunteerEmail = ?", (email,),).fetchall()

    if adminemail == [] and volunteeremail == []:
      value = {"present" : "No"}
      information.append(value)
    else:
      cursor.execute("""INSERT INTO codes(code, email) VALUES(?, ?)""", (hashed_code, email))
      connection.commit()
      value = {"present" : "Yes"}
      information.append(value)
      session.pop("code")

    connection.close()

    return jsonify(information)

# checks to see if code sent in email is valid
@application.route('/verify', methods=['POST'])
def verify():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    email = dataGet[0]['email']
    code = str(dataGet[1]["code"])

    salt = "v$rr!YP@ssw0rD?"
    dataBase_password = code+salt
    hashed = hashlib.md5(dataBase_password.encode())
    hashed_code = hashed.hexdigest()

    storedcode = cursor.execute("SELECT code FROM codes WHERE email = ? AND code = ?", (email, hashed_code),).fetchall()

    if storedcode == []:
      value = {"code" : "No"}
    else:
      value = {"code" : "Yes"}
      cursor.execute("UPDATE codes SET code = ? WHERE email = ?", (None, email))
      session["code"] = True

    connection.commit()

    connection.close()

    return jsonify(value)

# can change username and password. if username is the same and maps to email, then succeeds, otherwise errors out
@application.route('/newpass', methods=['POST'])
def newPass():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    email = dataGet[0]['email']
    password = str(dataGet[1]['password'])
    username = str(dataGet[2]['username'])
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    salt = "?Sew@!NtErNaT!0NaLh0urS?"
    dataBase_password = password+salt
    hashed = hashlib.md5(dataBase_password.encode())
    hashed_password = hashed.hexdigest()

    duplicate_email_v = cursor.execute("""SELECT COUNT(volunteerEmail) FROM volunteers WHERE volunteerEmail = ?""", (email,),).fetchall()
    duplicate_email = cursor.execute("""SELECT COUNT(adminEmail) FROM admins WHERE adminEmail = ?""", (email,),).fetchall()

    if duplicate_email_v == [(0,)] and duplicate_email == [(0,)]:
      return jsonify({"success": 'none'})

    duplicate_user = cursor.execute("""SELECT COUNT(volunteerUsername) FROM volunteers WHERE volunteerUsername = ?""", (username,),).fetchall()
    duplicate_user_a = cursor.execute("""SELECT COUNT(adminUsername) FROM admins WHERE adminUsername = ?""", (username,),).fetchall()
    data_username = cursor.execute("SELECT volunteerUsername FROM volunteers WHERE volunteerEmail = ?", (email,),).fetchall()
    data_username_admin = cursor.execute("SELECT adminUsername FROM admins WHERE adminEmail = ?", (email,),).fetchall()

    valid_username = ""

    if data_username == []:
      valid_username = data_username_admin[0][0]
    else:
      valid_username = data_username[0][0]


    if duplicate_user == [(1,)] or duplicate_user_a == [(1,)]:
      if username == valid_username:
        cursor.execute("UPDATE admins SET adminUsername = ?, adminPassword = ?, modifiedBy = ?, modifiedDate = ? WHERE adminEmail = ?", (username, hashed_password, username, dt_string, email))
        connection.commit()
        cursor.execute("UPDATE volunteers SET volunteerUsername = ?, volunteerPassword = ?, modifiedBy = ?, modifiedDate = ? WHERE volunteerEmail = ?", (username, hashed_password, username, dt_string, email))
        connection.commit()

        connection.close()

        return jsonify({"success": 'yes'})
      else:
        return jsonify({"success" : "no"})
    else:
      cursor.execute("UPDATE admins SET adminUsername = ?, adminPassword = ?, modifiedBy = ?, modifiedDate = ? WHERE adminEmail = ?", (username, hashed_password, username, dt_string, email))
      connection.commit()
      cursor.execute("UPDATE volunteers SET volunteerUsername = ?, volunteerPassword = ?, modifiedBy = ?, modifiedDate = ? WHERE volunteerEmail = ?", (username, hashed_password, username, dt_string, email))
      connection.commit()

      connection.close()

      value = {"success" : "yes"}

      return jsonify(value)

#shows the info in logged hours
@application.route('/logginginfo', methods=['POST'])
def loggingInfo():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]["username"]

    information = []
    approved = 0
    certified = 0
    rejected = 0
    unapproved = 0

    volunteerId = cursor.execute("SELECT volunteerId FROM volunteers WHERE volunteerUsername = ?", (username,),).fetchall()
    volunteerInfo = cursor.execute("SELECT volunteerFirstName, volunteerChapter FROM volunteers WHERE volunteerUsername = ?", (username,),).fetchall()

    volunteer_info = {"firstname" : volunteerInfo[0][0], "chapter" : volunteerInfo[0][1]}
    information.append(volunteer_info)

    submissionStatus = cursor.execute("""SELECT submissionStatus, totalHours FROM loggedHours WHERE volunteerId = ?""", (volunteerId[0][0],),).fetchall()

    for i in range(0, len(submissionStatus)):
      if submissionStatus[i][0] == "Approved":
        approved += submissionStatus[i][1]
      elif submissionStatus[i][0] == "Unapproved":
        unapproved += submissionStatus[i][1]
      elif submissionStatus[i][0] == "Certified":
        certified += submissionStatus[i][1]
      else:
        rejected += submissionStatus[i][1]
    
    submissionValue = {"approved" : approved, "certified" : certified, "unapproved" : unapproved, "rejected" : rejected}
    information.append(submissionValue)

    event_category = cursor.execute("SELECT eventCategoryName, categoryStatus FROM eventCategory WHERE eventCategoryChapter = ?", (volunteerInfo[0][1],),).fetchall()

    for i in range(0, len(event_category)):
      value = {"eventCat" : event_category[i][0], "eventCatStatus": event_category[i][1]}
      information.append(value)

    return jsonify(information)

#maps ervent category select box to event select box
@application.route('/map', methods=['POST'])
def map():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    eventCategory = dataGet[0]["eventcat"]
    username = dataGet[1]["username"]

    information = []

    volunteerChapter = cursor.execute("SELECT volunteerChapter FROM volunteers WHERE volunteerUsername = ?", (username,),).fetchall()

    eventCatMax = cursor.execute("SELECT maxAllowedHours FROM eventCategory WHERE eventCategoryName = ?", (eventCategory,),).fetchall()

    eventCategoryId = cursor.execute("""SELECT eventCategoryId FROM eventCategory WHERE eventCategoryName = ?""", (eventCategory,),).fetchall()
    if eventCategoryId != []:
      events = cursor.execute("""SELECT eventName, eventStatus FROM events WHERE eventCategoryId = ? AND eventChapter = ?""", (eventCategoryId[0][0], volunteerChapter[0][0],),).fetchall()
    else:
      events = []

    for i in range(0, len(events)):
      value = {"event" : events[i][0], "status" : events[i][1], "eventCatMax": eventCatMax[0][0]}
      information.append(value)

    return jsonify(information)

#populates the max allowed box for events
@application.route('/mapmax', methods=['POST'])
def mapMax():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    event = dataGet[0]["event"]

    information = []

    eventMax = cursor.execute("SELECT maxAllowedHours FROM events WHERE eventName = ?", (event,),).fetchall()

    if eventMax != []:
      value = {"event" : eventMax[0][0]}
      information.append(value)

    return jsonify(information)

#shows table info of loggedhours
@application.route('/tableinfo', methods=['POST'])
def ltableInfo():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]["username"]

    information = []
    id = 1

    volunteerId = cursor.execute("SELECT volunteerId FROM volunteers WHERE volunteerUsername = ?", (username,),).fetchall()

    logged_hour = cursor.execute("""SELECT loggedHourId, eventCategoryName, eventName, weekStart, weekEnd, totalHours, comments, submissionStatus FROM loggedHours 
    JOIN eventCategory ON loggedHours.eventCategoryId = eventCategory.eventCategoryId
    JOIN events ON loggedHours.eventNameId = events.eventNameId
    WHERE volunteerId = ? ORDER BY loggedHourId ASC""", (volunteerId[0][0],),).fetchall()

    for i in range(0, len(logged_hour)):
      eventCategoryName = logged_hour[i][1]
      eventName = logged_hour[i][2]
      week = logged_hour[i][3] + "   to   " + logged_hour[i][4]
      totalHours = logged_hour[i][5]
      comments = logged_hour[i][6]
      submission = logged_hour[i][7]
      values = {'id' : id, 'eventCat' : eventCategoryName, "eventName" : eventName, "week" : week, "totalHours" : totalHours, "comments" : comments, "submission" : submission}

      information.append(values)
      id += 1
    
    return jsonify(information)

#shows how many hours left till a medal
@application.route('/hoursleft', methods=['POST'])
def hoursLeft():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":

    dataGet = request.get_json()
    username = dataGet[0]["username"]

    birthday = cursor.execute("SELECT volunteerBirthday FROM volunteers WHERE volunteerUsername = ?", (username,),).fetchall()
    birthday = str(birthday[0][0])

    tokens = birthday.split("-")

    currentDateTime = datetime.now()
    dates = currentDateTime.date()
    year = dates.strftime("%Y")

    dt1 = date(int(tokens[0]), int(tokens[1]), int(tokens[2]))
    dt2 = date(int(tokens[0]), 6, 30)

    days = numOfDays(dt1, dt2)
    if(days < 0):
      age = int(year) - int(tokens[0]) - 1
    else:
      age = int(year) - int(tokens[0])

    if age >= 5 and age <= 10:
      value = {"bronze" : 26, "silver" : 50, "gold" : 75}
      return jsonify(value)
    elif age >= 11 and age <= 15:
      value = {"bronze" : 50, "silver" : 75, "gold" : 100}
      return jsonify(value)
    elif age >= 16 and age <= 25:
      value = {"bronze" : 100, "silver" : 175, "gold" : 250}
      return jsonify(value)
    elif age >= 26:
      value = {"bronze" : 100, "silver" : 250, "gold" : 500}
      return jsonify(value)
    
    return str()

#add volunteer hours to loghour page, but throws error if hour exceeds max allowed hours or if anything left blank
@application.route('/addhour', methods=['POST'])
def addHours():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()
  
  if request.method == "POST":
    dataGet = request.get_json()
    username = dataGet[0]["username"]
    eventCat = dataGet[1]["eventCat"]
    event = dataGet[2]['event']
    hours = dataGet[3]['hour']
    weekStart = str(dataGet[4]['weekStart'])
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    dt_string2 = now.strftime("%Y-%m-%d")

    id = cursor.execute("SELECT volunteerId FROM volunteers WHERE volunteerUsername = ?", (username,),).fetchall()
    eventId = cursor.execute("SELECT eventNameId FROM events WHERE eventName = ?", (event,),).fetchall()
    eventCatId = cursor.execute("SELECT eventCategoryId FROM eventCategory WHERE eventCategoryName = ?", (eventCat,),).fetchall()

    records1 = cursor.execute("SELECT totalHours FROM loggedHours WHERE volunteerId = ? AND eventCategoryId = ? AND eventNameId = ? AND submissionStatus = 'Approved'", (id[0][0], eventCatId[0][0], eventId[0][0],),).fetchall()
    records2 = cursor.execute("SELECT totalHours FROM loggedHours WHERE volunteerId = ? AND eventCategoryId = ? AND eventNameId = ? AND submissionStatus = 'Unapproved'", (id[0][0], eventCatId[0][0], eventId[0][0]),).fetchall()
    max_hours = cursor.execute("SELECT maxAllowedHours FROM eventCategory WHERE eventCategoryId = ?", (eventCatId[0][0],),).fetchall()
    max_hours_event = cursor.execute("SELECT maxAllowedHours FROM events WHERE eventNameId = ?", (eventId[0][0],),).fetchall()

    information = []

    events = cursor.execute("SELECT eventName FROM events WHERE eventCategoryId = ?", (eventCatId[0][0],),).fetchall()
 
    for i in range(0, len(events)):
      value = events[i][0]
      information.append(value)

    total_hours = 0
    for i in range(0, len(records1)):
      total_hours += records1[i][0]

    for i in range(0, len(records2)):
      total_hours += records2[i][0]
    
    
    if (total_hours + float(hours)) > float(max_hours[0][0]) and float(max_hours[0][0] != 0):
      value = {"exceeded" : "yes", "hoursleft": (int(max_hours[0][0]) - total_hours)}
      return jsonify(value)
    elif (total_hours + float(hours)) > float(max_hours_event[0][0]) and float(max_hours_event[0][0] != 0):
      value = {"exceed" : "yes", "hoursleft": (float(max_hours_event[0][0]) - total_hours)}
      return jsonify(value)
    else:
      tokens = weekStart.split('-')

      date1 = date(int(tokens[0]), int(tokens[1]), int(tokens[2]))
      date2 = date1 + timedelta(days=6)

      if event in information:
        cursor.execute("""INSERT INTO loggedHours(volunteerId, adminId, eventNameId, 
            eventCategoryId, weekStart,	weekEnd, submissionDate, totalHours, submissionStatus, comments, createdBy,	createdDate, modifiedBy, modifiedDate, numOfValidation, firstValidation)
            VALUES(?, NULL, ?, ?, ?, ?, ?, ?, "Unapproved", NULL, ?, ?, ?, ?, 0, NULL)""", (id[0][0], eventId[0][0], eventCatId[0][0], date1, date2, dt_string2, hours, username, dt_string, username, dt_string))

        connection.commit()
        return jsonify({"wrong" : "no"})

# allows for sql commands to be run in html text box and creates table to diplay result
@application.route('/execute', methods=['POST'])
def execute():
  connection = sqlite3.connect('sewawebapp.db')
  cursor = connection.cursor()

  if request.method == "POST":
    dataGet = request.get_json()
    sql = dataGet[0]["command"]

    if "SELECT" in sql:
      data = cursor.execute(sql).fetchall()
      headers = [i[0] for i in cursor.description]
      data.insert(0, headers)
      return jsonify(data)
    else:
      cursor.execute(sql)
      connection.commit()
      connection.close()
      return jsonify({})

if __name__ == "__main__":
  application.run(debug=True)