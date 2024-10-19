# 42-Darkly-OWASP

This project is a demonstration of the basics of web security and the OWASP Top 10 (Open Web Application Security Project). It includes auditing a simple website, which shows breaches that might show on well established websites that we use on a daily basis.

# The Breaches

## SQL Injection

An **SQL injection** is a security flaw that allows attackers to **interfere with database queries** of an application. This vulnerability can enable attackers to **view**, **modify**, or **delete** data they shouldn't access, including information of other users or any data the application can access. Such actions may result in permanent changes to the application's functionality or content or even compromise of the server or denial of service. To audit a web app for SQL injection vulnerabilities, there are a number of tools that can do it for us ( like SQLMap **)** but we’re not allowed use them for this project so we can only test manually. 

### Breach 1

We first need to get familiar with the app and identify input fields where user input is sent to the server, such as login forms, search boxes or URL parameters. After mapping all of the input fields in the app, we start to inject basic SQL payloads such as: `OR 1=1` or `OR 1=2` and observe any changes in the way the application responds. The payload `OR 1=1` is a common test for SQL injection, as it always evaluates to true and typically returns all records, whereas `OR 1=2` evaluates to false, meaning no records should be returned

After Trying this on the Members search on `http://10.12.100.97/?page=member&id=1&Submit=Submit` the application returned all the members that are in the database. Based on the response, it appears that the application is using a query similar to: `SELECT * FROM members WHERE id=$id_variable`. Injecting the payload modifies the query to `SELECT * FROM members WHERE id=$id_variable OR 1=1`, which fetches all records as 1=1 is always true

Now I’ll try to get as much information as possible, so I need to know what other columns exist in the members table, or even the other tables, so I’ll inject this query `1+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name=members` to the URL and this will get me all the columns in the members table, but this was a failure suggesting that the table **members** does not exist, luckily we could get all the tables and their columns by injecting this payload `1+UNION+SELECT+table_name,+column_name+FROM+information_schema.columns` and it seems like the table is named **users.** Now to get all the users information, since we already know what columns are there in the table, we could use this payload to achieve just that:

```sql
1+UNION+SELECT+user_id,+CONCAT(first_name,user_id,last_name,user_id,town,user_id,country,user_id,planet,user_id,countersign,user_id,Commentaire,user_id)+FROM+users
```

This payload combines user details by concatenating various fields, separated by the user ID for readability. This helps in identifying and parsing the data. Among the data that the application spitted out with this query I got this:

<aside>

```
ID: 1 UNION SELECT user_id, CONCAT(first_name,user_id,last_name,user_id,town,user_id,country,user_id,planet,user_id,countersign,user_id,Commentaire,user_id) FROM users
First name: 5
Surname : Flag5GetThe54254254255ff9d0165b4f92b14994e5c685cdce285Decrypt this password -> then lower all the char. Sh256 on it and it's good !5
```

</aside>

By splitting the data with the user_id which is 5, we could easily parse it into this :

- user_id: 5
- first_name: Flag
- last_name: GetThe
- town, country, planet: 42
- countersign: 5ff9d0165b4f92b14994e5c685cdce28
- Commentaire: Decrypt this password -> then lower all the char. Sh256 on it and it's good

The comment shows how to get the flag: `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`

### Breach 2

While exploring the application further, I discovered an image search field similar to the members search, located at `10.12.100.97/?page=searchimg&id=1&Submit=Submit`. Since this input field might be vulnerable to SQL injection as well, I decided to repeat the steps I had previously used. Using the same method as before, I retrieved the tables and their columns and found a table called `list_images` with three columns. I constructed the following query to concatenate and extract the data from the `list_images` table: `1+UNION+SELECT+id,+CONCAT(url,id,title,id,comment,id)+FROM+list_images`. This allowed me to retrieve image details from the database.

Among the retrieved data was the following output

<aside>

```
ID: 1 UNION SELECT id, CONCAT(url,id,title,id,comment,id) FROM list_images
Title: borntosec.ddns.net/images.png5Hack me ?5If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c465
Url : 5
```

</aside>

which again shows the exact way to get the flag: `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

### Preventing SQL Injections

SQL injection vulnerabilities can lead to serious data breaches, unauthorized access or system compromise. Therefore, it is critical to implement effective countermeasures to prevent this type of attack. Some key best practices to prevent SQL injections include:

- **Using parameterized queries**
    
    ```python
    # Example in Python using psycopg2 library:
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    ```
    
- **Input validating and sanitizing:**
While parameterized queries are the best defense, it’s also important to validate (ensure that user inputs conform to expected formats) and sanitize (escape dangerous characters like quotes, semicolons or special SQL) user inputs as a second layer of protection.
- **Using ORMs:**
Object-Relational Mapping frameworks (mostly) automatically use parameterized queries which reduces the risk of SQL injections.

## Broken Access Control

Access control is the application of constraints on who or what is authorized to perform actions or access resources. When improperly implemented, this can lead to broken access control, a vulnerability that allows attackers to access resources they shouldn't be able to, such as sensitive information or administrative functions. A common example would be unauthorized users gaining access to an admin dashboard or restricted pages.

### Breach 1

After throwing some random paths at the app URL to see if there are any hidden files that are not accessible through some link on the application, I found two interesting things: A `/admin` page and a `/robots.txt` file. The `robots.txt` file is typically used by websites to inform search engine crawlers which parts of the site should not be indexed. However, it’s important to note that this file is not a security feature—it's simply a request, and attackers can easily access the files it mentions if they’re not properly secured.

This is the robots file content: 

```python
User-agent: *
Disallow: /whatever
Disallow: /.hidden
```

In short, this file prevents all the crawling bots from indexing `/whatever` and `/.hidden`

While exploring the `/whatever` directory, I discovered a file called `htpasswd`, which typically stores user credentials (usernames and password hashes) for basic authentication in web servers. The content of this file was as follows:

```python
root:437394baff5aa33daa618be47b75cb49
```

Using CrackStation, I decrypted the hash and found that the password was `qwerty123@`. This appeared to be the password for the `root` user, so I attempted to log into the `/admin` page, and it worked and there was my flag: `d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff`

This vulnerability highlights broken access control, where sensitive files like the `htpasswd` file were accessible to unauthorized users. Proper access control mechanisms, such as restricting access to admin panels and sensitive files via authentication or server configuration, would have prevented this breach.

### Breach 2

Now moving to the `/.hidden` directory, which had a bunch of randomly named directories and sub directories with a readme files, most of which contained trolling messages but there has to be something somewhere so I wrote a python script to crawl through the directory tree and fetch all the files and their content, and in the middle of all the trolling messages there was a flag: `d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466`

### Preventing Broken Access Control

To prevent this kind of attack, the following best practices should be implemented:

- Ensure sensitive directories (like `/admin`) are protected by strong authentication and authorization mechanisms.
- Use proper access controls for files like `htpasswd`, ensuring they are not publicly accessible.
- Avoid exposing sensitive paths or files in `robots.txt`. Sensitive information should never rely on obscurity for security.

## Local File Inclusion

Local File Inclusion (LFI) is a vulnerability that allows an attacker to trick a web application into exposing or executing files on the server. This vulnerability typically occurs when an application uses user-supplied input to construct a path to a file without properly validating or sanitizing the input.

LFI is also known as directory traversal or path traversal because attackers exploit it by injecting `../` sequences into the file path to navigate the directory structure of the server.

### Breach

In this breach, I attempted a **directory traversal attack** to access sensitive files on the server. After brute-forcing multiple path sequences, I successfully accessed the `/etc/passwd` file using the following URL: `http://10.13.100.250/?page=../../../../../../../../etc/passwd` which spitted the flag `b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0`

### Preventing Local File Inclusion

To prevent Local File Inclusion vulnerabilities, several best practices can be implemented:

1. **Input Validation and Whitelisting**:
    - Validate and sanitize all user inputs. Ensure that only allowed paths are accessible by using a whitelist approach. For example, if the application allows loading files, strictly limit it to a specific directory and validate that the file path matches allowed files.
    - Reject any suspicious input that includes `../`, `%00`, or other common directory traversal patterns.
    - Always use **absolute paths** to reference files within the server rather than relying on user input to build file paths. This avoids the risk of directory traversal through relative paths.
    - Disable directory listings on the server, ensuring that attackers cannot easily see the file structure and attempt to access sensitive files.
    - Ensure that the application only has access to files and directories necessary for its operation. Critical system files like `/etc/passwd` should never be accessible by the web server.

## Cross-Site Scripting

Cross-site scripting (XSS) is a web security vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable application. It allows an attacker to circumvent the same origin policy, which is designed to segregate different websites from each other. Cross-site scripting vulnerabilities normally allow an attacker to masquerade as a victim user, to carry out any actions that the user is able to perform, and to access any of the user's data. If the victim user has privileged access within the application, then the attacker might be able to gain full control over all of the application's functionality and data.

### Stored XSS Breach:

Stored XSS (also known as persistent or second-order XSS) arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way, a comment section is a good example of a Stored XSS target.

While examining the application, I found a feedback page where you put your name and a feedback and then submit it to be displayed in the page, this is a prefect target for a Stored XSS attack.

I started with the name field and tried to inject some basic XSS keywords such as `alert` or `script` to see it the server is sanitizing the data, and that was enough to get the flag `0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e` I guess this is meant to be a basic demonstration of XSS.

### Reflected XSS Breach:

Reflected XSS is the simplest variety of cross-site scripting. It arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.

Back to the application, and while I was examining the source code of the landing page, I noticed that a certain image was served from this URL `?page=media&src=nsa` this suggested that the `src` parameter is used to dynamically include media files. I suspected that this variable might be vulnerable to reflected XSS.

I attempted to inject a simple payload using an HTML `<script>` tag to test this: `<script>alert(42)</script>` however, the application returned a "wrong answer" message. This indicated that the input was being processed or filtered, but not completely sanitized. The failure of this attempt confirmed that there was some vulnerability, though the input wasn't accepted in the exact format I was using.

Since the `src` parameter is expected to contain a media resource (likely an image), I decided to try a different approach by using a **data URL** to embed the payload. Data URLs allow for embedding small files (such as images) directly into the URL itself. In this case, I attempted to inject the following payload: `data:text/html,<script>alert(42)</script>` this successfully triggered the `alert(42)` function, confirming that the vulnerability existed, but I didn’t retrieve the flag. The reason for this was that the application was likely expecting a properly formatted image source in the `src` attribute, and a plain text script injection wouldn’t suffice. To ensure the payload is treated as an image, I encoded the script in **base64 format** and passed it as part of the `data` URL: `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` this encoded string represents `<script>alert(1)</script>`, which successfully triggered the XSS vulnerability, got me the flag: `928d819fc19405ae09921a2b71227bd9aba106f9d2d37ac412e9e5a750f1506d` 

### Preventing XSS

To prevent Cross-site scripting attacks, it is critical to ensure that any user input included in an HTTP response is properly handled. This can be done by:

1. Sanitizing Input: Always validate and sanitize any data provided by the user. Remove or escape any special characters like `<`, `>`, `'`, and `"` to prevent them from being interpreted as code by the browser.
2. Encoding Output: Ensure that all dynamic data included in HTML, JavaScript, or URLs is properly encoded. For instance, HTML encoding will convert `<script>` tags into harmless strings like `&lt;script&gt;`.
3. Use Secure Frameworks: Utilize frameworks that automatically escape and encode data before rendering it on the client-side, which significantly reduces the risk of XSS vulnerabilities.

## File Upload

File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size. Failing to properly enforce restrictions on these could mean that even a basic image upload function can be used to upload arbitrary and potentially dangerous files instead. This could even include server-side script files that enable remote code execution. In some cases, the act of uploading the file is in itself enough to cause damage. Other attacks may involve a follow-up HTTP request for the file, typically to trigger its execution by the server.

### Breach

There is only one place in our application where this breach could be possible which is the upload image page. The upload feature accepts only jpg files, so when I try to upload a php script for example I get a failure message, but all I had to do is to intercept the request to upload the php script using Buirp Suite and change the `content-type` header to `image/jpg` and it worked and got me the flag `46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8` It seems that the server only checks for the `content-type` header instead of the uploaded file itself.

### Preventing File Upload Exploitation

To prevent file upload vulnerabilities, web applications should implement several key security measures:

1. Strict File Type Validation: Using both client-side and server-side validation to ensure that only allowed file types (e.g., `.jpg`, `.png`) can be uploaded. Check the file's MIME type, but also verify the file extension and inspect the actual file content (using tools like `file` in Linux or similar libraries).
2. Limit File Size: Restrict the size of uploaded files to prevent denial-of-service (DoS) attacks by uploading excessively large files.
3. Sanitize File Names: Strip any special characters from file names and avoid using the original file name for storage. This prevents attackers from uploading files with malicious names designed to exploit file system behavior.
4. Use Secure Libraries: Rely on well-maintained libraries that handle file uploads securely, ensuring they sanitize inputs and implement safe handling practices by default.

## Login Brute Force

A brute-force attack is when an attacker uses a system of trial and error to guess valid user credentials. These attacks are typically automated using wordlists of usernames and passwords. Automating this process, especially using dedicated tools, potentially enables an attacker to make vast numbers of login attempts at high speed. 

### Breach

This one pretty straight forward, I used a dictionary of most common passwords that I found on Github with username `admin` to brute force login into the app, Buirp Suite has a tool called `intruder` which automates the brute forcing so all I had to do was to supply the dictionary of passwords and let it do the rest, and in no time I got the correct password and logged in to find the flag `b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2` 

### Preventing Brute Force Login Attacks

To protect against brute-force attacks, several mitigation techniques can be implemented:

1. Rate Limiting: Restrict the number of login attempts allowed from a single IP address within a certain time frame. For example, block or slow down requests after 3-5 failed login attempts within a few minutes.
2. Account Lockout: Temporarily lock accounts after several failed login attempts, alerting the account owner of the suspicious activity. However, be cautious with account lockouts as they can be exploited for denial-of-service attacks.
3. Captcha: Implementing CAPTCHA after a certain number of failed attempts can help verify that the login attempts are made by a human rather than an automated bot.
4. Two-Factor Authentication (2FA): Require users to authenticate with an additional factor (such as a one-time code sent to their phone) in addition to their password. This adds an extra layer of security even if the password is compromised.
5. Strong Password Policies: Enforce the use of strong, unique passwords that are difficult to guess or crack. Encourage users to avoid using common passwords.

## Recover Password Manipulation

Password recovery is one the most sensitive functions that application have to handle very carefully.

### Breach

This was an easy one too, just by inspecting the recover password page, I found a hidden input which had this email address  `webmaster@borntosec.com` and all I had to do was to change it to something like `hack@borntosec.com` and I got the flag `1d4855f7337c0c14b6f44946872c4eb33853f40b2d54393fbe94f49f1e19bbb0` 

### Preventing Password Recovery Manipulation

To protect against password recovery manipulation vulnerabilities, the following security measures should be implemented:

1. Input Validation and Sanitization: Ensure that all user input fields, including hidden inputs, are properly validated and sanitized on the server side to prevent manipulation.
2. User Verification: Before allowing a password reset, verify the identity of the user through additional factors such as sending a time-limited token to the registered email or phone number of the account owner.
3. Disable Hidden Fields for Sensitive Information: Avoid using hidden input fields to store sensitive information such as emails or user IDs in password recovery forms. Instead, retrieve these values from the server based on authenticated user sessions.

## Server-Side Request Forgery

Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location.

In a typical SSRF attack, the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connect to arbitrary external systems. This could leak sensitive data, such as authorization credentials.

### Breach

Usually when pentesting for SSRF, we should be looking for parts where the application makes requests to URLs of either internal or external services, in this application the only such case is the social media redirections, so I change the site to `localhost:8000` and there was my flag: `b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3`

### Preventing SSRF Attacks

To prevent SSRF vulnerabilities, several important security measures should be implemented:

1. Whitelisting: Implement strict whitelisting of URLs or IP ranges that the server is allowed to access. Requests should only be made to trusted services and domains, and connections to internal or private IP addresses should be explicitly blocked.
2. Input Validation: Properly validate and sanitize all user inputs, particularly URLs, to ensure that attackers cannot manipulate request destinations. Block common SSRF payloads such as IP addresses in the internal ranges (e.g., 127.0.0.1, 169.254.169.254).
3. Network Access Limiting: The application should have limited network access, especially to sensitive internal services. Use firewall rules to restrict the server’s ability to connect to internal networks unless absolutely necessary.
4. Use URL Parsers Carefully: Avoid relying solely on the `Host` header or superficial URL checks to validate requests. Instead, use well-maintained libraries for parsing URLs to properly detect whether the request is heading to an internal or external service.
5. Monitor Requests: Implement logging and monitoring of outgoing requests to detect any anomalous or suspicious activity. Additionally, alert on attempts to access restricted resources like internal services.
6. Disable Unnecessary Protocols: If possible, restrict the protocols that can be used in server requests (e.g., block protocols like `file://`, `ftp://`, or `gopher://` if not needed) to prevent abuse.

## Cookie Manipulation

### Breach

I noticed a cookie with the name `I_am_admin` in the application requests and it had what seemed like an encrypted value, so I used Crackstation to crack the MD5 hash, which revealed the original value as `false`

MD5 is an outdated and insecure hashing algorithm, and tools like Crackstation maintain large precomputed databases of hashed values, making it easy to reverse or crack weak hashes like MD5. By modifying the value of the `I_am_admin` cookie to `true`, I was able to bypass authentication checks, as the application relied solely on this cookie to determine user privileges so I got the flag: `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3` 

### Prevention

- Do not store sensitive information in cookies: Cookies should store session identifiers rather than user roles or sensitive information.
- Use server-side checks: Authentication decisions should be made on the server-side, not based on client-side data like cookies. The server should validate user roles using secure session data.
- Use stronger hashing algorithms: If hashes are necessary, algorithms like SHA-256 or stronger with salting should be used to make cracking harder.
- Secure your cookies: Ensure cookies are set with the following flags:
    - `HttpOnly`: Prevents access to the cookie via JavaScript, reducing the risk of XSS.
    - `Secure`: Ensures the cookie is only sent over HTTPS.
    - `SameSite`: Helps prevent CSRF attacks.

## Business Logic

Business logic vulnerabilities are flaws in the design and implementation of an application that allow an attacker to elicit unintended behavior. This potentially enables attackers to manipulate legitimate functionality to achieve a malicious goal. These flaws are generally the result of failing to anticipate unusual application states that may occur and, consequently, failing to handle them safely. 

### Breach

I found a business logic vulnerability in this app by inspecting the survey page. The page has a list of subjects (ranked by average grade) and the user is supposed to chose one subject and give them a grade between 1 and 10, I tried to manipulate the ranking of subjects by changing one of the values in the list of grades to a ridiculous number such as 1000000 and I got the flag `03a944b434d5baff05f46c4bede5792551a2595574bcafc9a6e25f67c382ccaa` this means that the server does not validate the grade.

### Preventing Business Logic Attacks

Preventing business logic vulnerabilities requires a careful approach to the design and implementation of an application’s functionality:

1. Input Validation: Always validate all inputs on both the client and server sides, especially when dealing with user-modifiable data like rankings, votes, or grades. Ensure that values fall within expected ranges (e.g., grades between 1 and 10).
2. Enforce Business Rules on the Server: Business rules and constraints should always be enforced on the server side, as client-side restrictions (like HTML form limits) can easily be bypassed. For example, the server should reject grades that are outside the allowed range.

## User-agent and Referer

When a web browser requests a page from a web server, it sends out a string containing information on the platform, operating system and software installed on the requesting computer. The web server can then use this information in order to better customize the page content for that particular browser. The best example would be to send a version of the page that is better laid out for mobile devices. This string is called the `User-Agent` string.

`User-Agent` strings have many forms, and typically look similar to one of the following examples: 

- Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1866.23 Safari/537.36
- *Mozilla/5.0 (iPad; CPU iPhone OS 9_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Mobile/12A405*
- *Mozilla/5.0 (Linux; Android 4.0.4; HTC Desire P Build/IMM76D) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Mobile Safari/535.19*

The [`Referer`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer) header contains the address of a request (for example, the address of the previous web page from which a link to the currently requested page was followed, or the address of a page loading an image or other resource). This has many fairly innocent uses, including analytics, logging, or optimized caching.

### Breach

Again while inspecting pages of the application, I found a weird comment in the copyright page  `/index.php?page=e43ad1fdc54babe674da7c7b8f0127bde61de3fbe01def7d00f151c2fcca6d1c` that says, among other things:

> You must come from : "https://www.nsa.gov/"
> 

> Let's use this browser : `ft_bornToSec` It will help you a lot.
> 

This could mean that the `User-Agent` should be `ft_bornToSec` and `referer` is the NSA website, so I tried that using the curl command:

```bash
curl -A "ft_bornToSec" -e "https://www.nsa.gov/" http://10.13.100.250/index.php\?page\=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f | grep flag
```

And the app responded with the flag `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

### Prevention

Headers like `User-Agent` and `Referer` are client-controlled, meaning they can easily be spoofed or modified by attackers using tools like curl, browser developer tools, or extensions. This makes them unreliable for security mechanisms such as access control or authentication.
