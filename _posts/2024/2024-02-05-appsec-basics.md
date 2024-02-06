---
title: Java Application Security Examples
date: 2024-02-05 00:00:00 +/-0000
categories: [general,notes]
tags: [resources]     # TAG names should always be lowercase
image:
    path: /assets/images/appsec.jpg
---

## Introduction

In this post, we are going to go over some of the classic vulnerabilities that can emerge in Java code and what we might do to help mitigate them. Through this survey, you should be able to better understand how certain misconfigurations/oversights can lead to security compromises of Java your applications.

## Vulnerabilities

### SQL Injection

SQL injection occurs when untrusted user input is allowed to be passed directly to a backend SQL query. When exploited, it allows a malicious actor to pass in content that directly alters the behavior of the query and - ultimately - the application itself. This can lead to effects like information disclosure, authentication bypasses, and even remote code execution. In a Java app, vulnerable code might look like:

```java
String username = request.getParameter("user");
String password = request.getParameter("password");

String sql = "select * from users where (username = '" + username +"' and password = '" + password +"')";

Conncection connection = pool.getConnection();
Statement statement = connection.createStatement();
ResultSet result = statement.executeQuery(sql);

if (result.next()){
    loggedIn = true;
    //successful login logic
} else {
    //authentication failure logic
}
```

* To validate user credentials, the `request.getParameter()` method is first called to extract the username from the HTTP request parameter.
* The same is done to grab the password.
* A `sql` string is declared, representing the SQL query to be used to authenticate the user. The fetched `username` and `password` are concatenated into the string to build the final query.
* The SQL query defined in `sql` is passed to `statement.executeQuery()`, which makes the query against the backend SQL server and returns a `ResultSet` object; this is checked in the concluding if/else block to determine whether the user logs-in.

#### Example Exploit

In the above Java code, what happens if the user enters the following **username** and **password**?

|username|password|
|---|---|
|victimizedUser|' or 1=1)#|

Such an entry would get passed to the `sql` string in the above Java code, creating the following SQL query:

```sql
SELECT * from users where (username = '"victimizedUser"' and password = '"' or 1=1)#"')"
```

In effect, this returns any entry that matches the username "victimizedUser"; it doesn't matter that the account doesn't have a matching password of `"`, since the predicate is satisfied by the evaluation of `1=1`, which is always `TRUE`. In essence, this permits a malicious actor to login without knowing the actual password of the `victimizedUser` user.

#### Fixed Code

```java
String username = request.getParameter("user");
String password = request.getParameter("password");

String sql = "select * from users where username = ? and password = ? "

Conncection connection = pool.getConnection();
PreparedStatement preparedStatement = connection.prepareStatement(sql);
preparedStatement.setString(1,username);
preparedStatement.setString(2,password);

if (result.next()){
    loggedIn = true;
    //successful login logic
} else {
    //authentication failure logic
}
```

* First, we've modified the `sql` string with `?` symbols which act as placeholders for Java's `PreparedStatement` class.
* The `connection.prepareStatement()` method precompiles the SQL query and creates a `preparedStatement` object. This object is used for sending parameterized SQL statements to the backend SQL server.
* The `setString()` method passes the **username** and **password** parameter values to the prepared statement.
* **Prepared Statements** are used to abstract SQL statement syntax from input parameters. Statement templates are first defined at the application layer, and the parameters are then passed to them. Aside from a better protection against SQL injection attacks, prepared statements offer improved code quality and maintainability.

Ultimately, the security payoff with using prepared statements is that the database will ensure the parameters are automatically escaped.

### XXE Processing

XML eXternal Entity (XXE) processing attacks work by taking advantage of XML's ability to load external resources into the document. By submitting an XML file that defines an external entity with a **file://** URI, an attacker can effectively trick the application's SAX parser into reading the contents of arbitrary file(s) that reside on the server-side filesystem. In a Java app, vulnerable code might look like:

```java
public class ExampleDocumentBuilderFactory {
    public static DocumentBuilderFactory newDocumentBuilderFactory(){
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance()
        try {
            documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities",true);
            documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities",true);
        } catch(ParserConfigurationException e){
            throw new RuntimeException(e);
        }
        return documentBuilderFactory;
    }
}
```

* The server-side SAX parser uses the `DocumentBuilderFactory` class, which is part of the Java API for XML processing (JAXP).
* In order to parse incoming XML files, a new instance of JAXP `DocumentBuilderFactory` is created using `newInstance()`.
* A number of features are set on how XML documents are processed by the SAX parser.
  * Enabling `external-general-entities` and `external-parameter-entities` permits the SAX parser to load external entities, which can be abused by a malicious actor. Were these set to `FALSE`, the SAX parser would automatically reject the referencing.

#### Example Exploit

Given the above Java code, what happens if the user provides an XML document with the following data?

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ELEMENT foo ANY> 
<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<stockCheck>
    <productId>&xxe;</productId>
</stockCheck>
```
The `DOCTYPE foo` declaration references an external **Document Type Definition (DTD)** file, which has been arbitrarily named "foo". The XML declaration `ELEMENT foo ANY` declares that `foo` DTD can contain any combination of parsable data. Finally, we use the XML declaration `ENTITY` to load additional data from an external resource. The syntax for the `ENTITY` is `ENTITY name SYSTEM URI`, where **URI** is the full path to a remote URL or local file. Finally, we map our tag `foo` to the external entity `&xxe;` that points to `"file:///etc/passwd"`.

In effect, when our Java code's SAX parser processes this XML document, any instance of `&xxe;` will get replaced by the contents of the local `/etc/passwd` file.

#### Fixed Code

```java
public class ExampleDocumentBuilderFactory {
    public static DocumentBuilderFactory newDocumentBuilderFactory(){
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance()
        try {
            documentBuilderFactory.setFeature("http://xml.org/sax/features/disallow-doctype-decl",true);
            documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities",false);
            documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
        } catch(ParserConfigurationException e){
            throw new RuntimeException(e);
        }
        return documentBuilderFactory;
    }
}
```

* Setting the SAX parser to `disallow-doctype-decl` configures the application's XML parser to not allow DOCTYPE declarations. This throws an exception and stops parsing if such content is present, preventing the vulnerability from exposing sensitive information.
* Since `DOCTYPE` declarations must oftentimes be allowed, we can alternatively configure the server-side SAX parser to prevent decalaring external entities.

Because each XML parsing engine has its own particular configuration mechanisms, the above code may not be applicable to your particular app. However, each should have its own means for disabling inline DTD to prevent XXE.

### Command Injection

A command injection vulnerability allows malicious actors to execute system commands directly on the back-end host. This kind of remote code execution is quite serious because it ostensibly provides a foothold for attackers on your network/domain. In a Java app, we might see vulnerable code like:

```java
public class CommandExecutor {
    public string executeCommand(String userName){
        try {
            String helloworld = "Hello " + userName;
            Runtime rt = Runtime.getRuntime();
            rt.exec("/usr/bin/echo " + helloworld);
            //Application logic for returning output to browser

        } catch(Exception e){
            e.printStackTrace();
        }
    }
}
```

* In the above code, our application takes in a username and calls the `java.lang.Runtime.exec()` function. This in turn echoes the string "Hello <username>". This output is eventually returned back to the browser.

#### Example Exploit

Given the above Java code, what happens if the user provides the following input in lieu of a valid username?

**victimizedUser; cat /etc/passwd**

When combined together with the existing `exec()` string, we get:

**/usr/bin/echo victimizedUser; cat /etc/passwd**

The semi-colon `;` is one of several logical operators that allow for chaining together multiple commands in Linux. In essence, it runs the following commands in sequence:

* `echo victimizedUser`
* `cat /etc/passwd`

The first command performs as the Java program intended; the second is an arbitrarily injected command to read the local /etc/passwd file. In this case, a malicious actor could choose from a variety of commands to run (including potentially attaining a direct foothold on the host machine).

#### Fixed Code

```java
public class CommandExecutor {
    public string executeCommand(String userName){
        try {
            String helloworld = "Hello " + userName;
            if (!Pattern.matches("[0-9A-Za-z]+", userName)){
                return false;
            }
            Runtime rt = Runtime.getRuntime();
            rt.exec("/usr/bin/echo " + helloworld);
            //Application logic for returning output to browser

        } catch(Exception e){
            e.printStackTrace();
        }
    }
}
```

* In the above-modified code, an additional check screens the username to ensure it only contains valid characters. Assuming we enforced an appropriate policy at the time of account creation, usernames in this `executeCommand()` function could reasonably be expected to be composed strictly out of alphanumeric characters.
* We could further enhance the security of this program a number of ways, such as not accepting user-supplied `userName` values. A better way would be to pull the user's `userName` from a database record or static index variable set during the account's creation.

Both of these would be perfectly reasonable fixes.

### Session Fixation

Session Fixation occurs when a malicious actor can predetermine a valid session identifier and subsequently trick a user into logging into the application using the aforementioned session ID. Once the user logs in, the attacker can follow-up with **session hijacking**, performing actions as the user. In a Java app, we might see vulnerable code like:

```java
private Boolean authenticate(HttpServletRequest request, String credential, String password){
    try{
        request.getSession(true);
        if(request.getUserPrincipal() == null){
            request.login(credential,password);
        }
        return true;
    } catech(ServletException e){
        log.log(Level.WARNING, "Error authenticating", e);
    }
    return false;
}
```

* The `authenticate` function is called for authenticating users and accepts 2 string parameters as its function arguments.
* The function calls `login()`, which verifies the user's credentials.

#### Example Exploit

Given the above Java code, let's assume that the session ID is leaked as a part of the URL like so:

**https://myapp.com/login?app_session_id=7815696ecbf1c96e6894b779456d330e**

The above example is arbitrary; perhaps the session ID is leaked in an HTTP response header or perhaps the session IDs are predictable. Either way for the example's sake, let's assume that a malicious actor is able to determine the session ID that the application will assign to a user upon authenticating. In this case, they might use the above in a fishing attempt to get a valid user to login with said session ID; when they have, the malicious actor can then likewise copy that session ID (since it was predetermined and known) and then have a valid session as said user, effectively performing session hijacking.

#### Fixed Code

```java
private Boolean authenticate(HttpServletRequest request, String credential, String password){
    HttpSession session = request.getSession(false);
    if (session != null){
        session.invalidate();
    }
    try{
        request.getSession(true);
        if(request.getUserPrincipal() == null){
            request.login(credential,password);
        }
        return true;
    } catech(ServletException e){
        log.log(Level.WARNING, "Error authenticating", e);
    }
    return false;
}
```

* In the above, we've added a `request.getSession()` call upfront to extract the existing session token early on.
* The existing session is invalidated (and therefore cannot be used by a malicious actor) via `session.invalidate()`.
* Finally, a new session identifier is generated for the user by invoking `request.getSession(true)`. This ensures that the user has a different session identifier than whatever they may have initially have had upon arriving at the app, mitigating session fixation.

### CWE-330: Use of Insufficiently Random Values

Random numbers are relied upon all the time in cryptography. They're used in key generation, initialization vectors, nonces, and other elements that contribute to cryptographic algorithms. If the numbers are pseudo-random (or otherwise predictable), a malicious actor could potentially predict the generated keys/nonces, compromising the security of the cryptographic system. In a Java app, we might see vulnerable code like:

```java
protected String newSession(){
    long now = System.currentTimeMillis();
    return encode(now);
}

private String encode(long time){
    return new String(Long.toString(time));
}
```

* The above code is representative of a session generator.
* As a bespoke session management API, the core logic for generating the session token values is implemented within the `newSession` method.
* Unfortunately, instead of using a sufficiently random number generator, the sessions naively rely on `System.currentTimeMillis()` for uniqueness. This method returns the current time (in milliseconds) which is then passed to an encoding function.
* Once encoded, the returned session identifier is used by the session management API, ultimately assigning weak session identifiers.
* This code is ultimately vulnerable because a malicious actor familiar with the encryption algorithm can predict the session of logged-in users by sequentially bruteforcing the `currentTimeMillis()` value.

#### Fixed Code

```java
protected String newSession(){
    SecureRandom rand = new SecureRandom();
    byte bytes[] = new byte[20];
    rand.nextBytes(bytes);
    String cookie = new String(Hex,encodeHex(bytes));
    return cookie
}
```
* Java can generate a series of cryptographically secure random numbers through `java.security.SecureRandom`.
* We store 20 bytes of random data to `bytes[]` through calls to `rand.nextBytes()`.
* Those bytes are hex encoded before being assigned to the string variable `cookie`.
* This new implementation ensures that the returned cookie value is sufficiently random to not allow prediction of session IDs, preserving session integrity and confidentiality.

### Reflected XSS

Cross-Site Scripting (XSS) affect client-side users directly by surreptitiously injecting 

Cross-Site Scripting (XSS) attacks include a wide-range of possible attacks, including the injection of executable Javascript. Being able to execute Javascript inside a user's browser can springboard a variety of follow-up actions, such as changing a user's password, cryptocurrency mining, and more. **Reflected** XSS are instances where such input reaches the back-end server and gets returned to us without being filtered or sanitized; these are typically temporary as once we navigate away from the page, the code will not be executed again. In a Java app, we might see vulnerable JSP code like:

```java
<c:when test="${f:h(allRecordCount) != 0}">
<jsp:include page="searchResults.jsp"/>
</c:when>
<c:otherwise>
    <h4>No results found for: </h4>
    <p><em><strong><%= request.getParameter("search") %></strong></em></p>
</c:otherwise>
```

* The above code is representative of a web page's search functionality. This uses JSP Standard Templating Library (JSTL), which provides standard actions and methods for formatting/rendering HTML pages.
* When rendering search results, the `c:when` conditional tag is called to check if any search results were returned by the server, which are then formatted/rendered by `searchResults.jsp`.
* The `c:otherwise` conditional tag fires if no results are returned.
* To render the "No results found for" message, `request.getParameter()` is called on to extract the `search` parameter from the URL, getting directly rendered as a JSP expression.

The above is vulnerable to reflected XSS because the JSP expression language does not escape expression values. In the above instance, if the `search` parameter includes HTML-formatted data, Java's EL expression will simply render the string without escaping/encoding it.

#### Fixed Code

```java
<c:when test="${f:h(allRecordCount) != 0}">
<jsp:include page="searchResults.jsp"/>
</c:when>
<c:otherwise>
    <h4>No results found for: </h4>
    <p><em><strong><c:out value="${<%= request.getParameter("search") %>}"/></strong></em></p>
</c:otherwise>
```
* The most effective method of protecting against XSS attacks in this case is using HSTL's `c:out` tag or `fn:escapeXml()`. Either of these escape and encode HTML characters.

### Stored (Persistent) XSS

Unlike reflected XSS (which we just covered), Stored/Persistent XSS payloads are stored in the back-end database and retrieved whenever a user visits a page that would fetch the content (e.g. comments to a blog post, tasks in a to-do list, etc.). In a Java app, we might see vulnerable JSP code like:

```java
<table>
    <c:forEach var="contact" iterms="${contacts}">
        <tr>
            <td>${contact.name}</td>
            <td>${contact.title}</td>
            <td>${contact.number}</td>
        </tr>
    </c:forEach>
</table>
```
* This JSP code reflects a kind of contacts list application.
* To populate the `table` tag, the `c:forEach` tag is called to iterate over the collection of contact objects returned by the backend database.
* Each `contact` object is rendered within the `td` tags using Java's JSP expression language (EL) syntax `${}`.

Once more, the above is vulnerable to XSS because the JSP expression language does not escape expression values. If a malicious actor saves a contact card with HTML-formatted data in any of the **name**, **title**, or **number** fields, the Java EL will simply render the input without escaping or encoding it. This means *any* user who pulls that card will render that code *every* time.

#### Fixed Code

```java
<table>
    <c:forEach var="contact" iterms="${contacts}">
        <tr>
            <td><c:out value="${contact.name}"/></td>
            <td><c:out value="${contact.title}"/></td>
            <td><c:out value="${contact.number}"/></td>
        </tr>
    </c:forEach>
</table>
```

* The most effective method of protecting against XSS attacks in this case is using HSTL's `c:out` tag or `fn:escapeXml()`. Either of these escape and encode HTML characters.

### DOM XSS

Unlike Stored/Reflected XSS, DOM XSS has malicious actors injected into the browser's document object model (making it difficult to prevent and highly context-specific); malicious actors may inject HTML, HTML attributes, CSS, or URLs, for example. For DOM XSS, the injection happens directly into the application during runtime for the client.

```java
<h6>
<script>
    var name = document.location.hash.split('#')[1];
    document.write("Hello " + name);
</script>
</h6>
```
In the above example, we assume the code is dynamically pulling from a supplied url (e.g. https://vulnerablesite.com/landing#username). This is vulnerable in a number of ways, not the least of which is uncontrolled input supplied directly to the javascript embedded within the `h6` header tags.

```java
<h6>
<script>
    if (name.match(/^[a-zA-Z0-9]*$/)){
        var textNode = document.createTextNode("Hello " + name);
        document.querySelector('h6').appendChild(textNode);
    } else {
        window.alert("Error!");
    }
</script>
</h6>
```

* In the modified code, an additional check is introduced which performs input validation against the `name` variable.
* Javascript's `match()` method performs a regex search, identifying non-alphanumeric characters common in such injections.
* We've also embraced javascript's `document.createTextNode()` method, which interprets the submitted contents as text, regardless of whether what gets passed is HTML-formatted.
