# VulnerableWebsite
VulnerableWebsite is a purposefully vulnerable web application intended to be used as a Capture The Flag (CTF) challenge. Through a series of tasks, users will navigate through different layers of security (or the lack thereof) to capture the flag, learning and applying various cybersecurity concepts along the way.

# Overview

*The challenge begins at the login page, where participants need to find the credentials for the admin user to proceed. As they progress, they will be required to crack passwords, gather open-source intelligence (OSINT) from user profiles, and answer security questions based on the information they've collected. Each step builds upon the previous, leading to a comprehensive learning experience in web application security.* 

**Getting Started**

    Download The Following Iso FIle
    (PlaceHolder)
    Ensure Your Local Server Is Running Via VM
    URL: http://localhost:8080/
    Navigate To The URL Above To Begin The Challenge.

# Dependencies(May Or May Not Be Needed)
    go get -u golang.org/x/crypto/bcrypt
    go get -u golang.org/x/crypto/bcrypt

# Support

For any issues or inquiries regarding VulnerableWebsite, feel free to open an issue on this GitHub repository, and we'll get back to you as soon as possible.


# Step-By-Step Walkthrough Below

**Step 1: Login Page**

URL: http://localhost:8080/
Objective: Gain access to the admin dashboard by logging in.

Hint: Check the console for a hint regarding the username.

**Solution:**

    Username: admin
    Password: password123 (Obtained via brute force due to no rate limit

**Step 2: Admin Dashboard**

Objective: Retrieve and crack the hashed password of 'user1'.

*In Kali Linux, John the Ripper could be utilized to crack the hashed password of 'user1' in Step 2 of this challenge. It supports various hash algorithms and is capable of auto-detecting the hash type.*

**Solution:**

    Cracked Password: userpassword

**Step 3: User1 Login**

Objective: Log in as 'user1' using the cracked password.

**Solution**

    Username: user1
    Password: userpassword

**Step 4: OSINT (Open-source intelligence)**

Objective: Gather information from 'user1's tweets for the next steps.

**Information Gathered:**

    Love for cats from tweet "I love cats"
    Birth year 1998 deduced from tweet "Can't Believe I'm 25 Today!" dated 2023-10-30

**Step 5: Email Login**

Objective: Log in to 'user1's email.

**Solution**

    http://localhost:8080/email_login (Obtained by clicking the email hyperlink on 'user1's page)
    Email: User1@realmail.com
    Password: ILoveCats (Obtained via brute force using the information from tweets)

**Step 6: Security Question**

Objective: Answer the security question correctly to capture the flag.

**Solution**

    Security Question: What Year Were You Born?
    Answer: 1998

**Congratulations! You've successfully navigated through each step of this CTF challenge and captured the flag.**








