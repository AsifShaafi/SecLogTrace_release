# Train-Ticket Coverage Sweep — Instructions

**For:** the person running the browser session
**Time needed:** about 2 hours, plus 15 minutes of setup
**You need:** a laptop, a browser, and Python 3. No server access, no VPN
to the backend, no command-line knowledge beyond running one script.

---

## What this is and why it matters

Train-Ticket is a microservice benchmark: a fake train-booking website made
of about 44 separate backend services. Every click you make in the website
produces a *trace* — a record of which backend services talked to each other
to answer that click.

We are building a research dataset of these traces. Right now we only have
traces from one narrow flow (searching and booking a ticket), which means
most of the 44 services have never been recorded.

**Your job is to touch as many different features of the website as
possible, in a controlled way, while we record what the backend does.**

You are not testing the site. Things breaking is a useful result, not a
failure. Just write down what happened and move on.

The one thing that would make the session useless is if we cannot tell
*when* you did *what*. That is why the timing rules below matter more than
the feature list.

---

## Part 1 — Setup (do all of this before you touch the website)

### 1.1 Confirm the window is yours

- [ ] Confirm with Shaafi that the system is reserved for you right now

Nobody else can use the site during your session. If someone else clicks
around at the same time, their traces and yours mix together and neither
of us can tell them apart afterwards. Message him when you start and when
you finish.

### 1.2 Check your computer's clock

- [ ] Open **https://time.is** in a browser tab
- [ ] It will show how far off your clock is, e.g. "Your time is exactly
      correct" or "0.4 seconds behind"
- [ ] Write the result down. If it says you are **more than 30 seconds
      off**, stop and tell Shaafi before continuing

Everything we extract afterwards is pulled by timestamp. A clock that is
five minutes off means we pull the wrong five minutes of data.

### 1.3 Get the session logger running

- [ ] Put `session_log.py` (attached) in a folder you can find
- [ ] Open a terminal or command prompt in that folder
  - **Mac:** open Terminal, type `cd `, drag the folder onto the window,
    press Enter
  - **Windows:** open the folder in File Explorer, click the address bar,
    type `cmd`, press Enter
- [ ] Run it:
  - Mac / Linux: `python3 session_log.py`
  - Windows: `py session_log.py`
- [ ] You should see a banner with a session start time and a `[  1] >`
      prompt

Leave this terminal window open beside your browser for the whole session.
**You never type a timestamp yourself** — the script does it.

How you use it, for each thing you do:

```
[  1] > log in as fdse_microservice        <- type what you're ABOUT to do, press Enter
                                           <- now go do it in the browser
[  1] > ok                                 <- it worked
[  2] > search trips nanjing to shanghai
[  2] > fail empty results list            <- it did not work, say why
[  3] > book a ticket
[  3] > note the page took ~10 seconds     <- optional extra comment
[  3] > ok
```

Four commands only: a **description**, then `ok`, or `fail <reason>`, or
`note <comment>`. Type `done` at the very end.

### 1.4 Start the browser network recording

This captures every request automatically, so we get a precise record even
if your written log is patchy.

**Chrome or Edge:**
- [ ] Open a **new window** (not a tab you have other things in)
- [ ] Press `F12` to open DevTools
- [ ] Click the **Network** tab
- [ ] Tick the **Preserve log** checkbox — this is essential, without it
      the record is wiped every time the page navigates
- [ ] Leave DevTools open for the entire session. Closing it stops the
      recording.

**Firefox:**
- [ ] Press `F12`, click **Network**
- [ ] Click the gear icon on the right, make sure **Persist Logs** is ticked
- [ ] Leave DevTools open for the entire session

- [ ] Confirm you can see requests appearing when you load a page

### 1.5 Open the site

- [ ] Go to **http://<research-host>:32677/**

Accounts (these are the benchmark's built-in demo accounts, not real
credentials):

| Role | Username | Password |
|---|---|---|
| Regular user | `fdse_microservice` | `111111` |
| Admin | `admin` | `222222` |

**Do not use `admin` / `admin`.** That specific combination triggers a
deliberately injected fault in this deployment and will pollute the data.

---

## Part 2 — Ground rules

These four rules matter more than how many features you get through. If you
only remember one thing, remember rule 3.

### Rule 1 — Pause 20 to 30 seconds between actions

Count to twenty between finishing one thing and starting the next. Traces
that arrive back-to-back are hard to attribute to a specific feature
afterwards. The gaps are what let us separate them.

This is why the session takes two hours for what feels like twenty minutes
of clicking. The waiting is the point.

### Rule 2 — Click once, then wait

Do not double-click buttons. Do not click again because the page seems
slow. Give every action a full 15 seconds to respond before deciding it
failed.

### Rule 3 — Never retry a failure more than once

**This is the most important rule on the page.**

If something fails, log it with `fail <reason>` and move on. At most, try
it one more time.

The reason: this dataset is for *security anomaly detection*. Repeated
failed logins are exactly what a brute-force attack looks like. Rapid
repeated identical requests are exactly what a denial-of-service attack
looks like. If you retry a broken login eight times in frustration, you
have injected attack-shaped traffic into what is supposed to be our clean
normal baseline, and we will not be able to tell it apart from a real
attack later.

Failures are data. Log them and keep going.

### Rule 4 — Do not delete or edit anything you did not create

The admin panel can delete stations, routes, and trips. Some of those were
carefully seeded and took a long time to get working. Deleting one breaks
the environment for everyone.

- **Viewing** anything in admin: always fine
- **Creating** in admin: fine, but the name must start with `sweep_`
  (e.g. `sweep_teststation`)
- **Editing or deleting**: only things you created this session, with the
  `sweep_` prefix
- **Cancelling an order**: fine if it is an order you placed this session

---

## Part 3 — The walkthrough

Work down the list in order. Log each one before you do it.

If a feature does not exist in this version of the site, or the page is
blank, or a button does nothing — log it as `fail` with what you saw and
move to the next. That is genuinely useful information.

Do not skip ahead to the interesting-looking ones. The order matters
because later steps depend on earlier ones (you cannot pay for an order
you never created).

### Section A — Account (5 actions)

- [ ] A1. Register a brand new account (username starting with `sweep_`)
- [ ] A2. Log out
- [ ] A3. Log in with the account you just registered
- [ ] A4. Log out
- [ ] A5. Log in as `fdse_microservice` / `111111`

Stay logged in as `fdse_microservice` for Sections B through E.

### Section B — Searching and browsing (6 actions)

- [ ] B1. Search for high-speed trains (G / D types) between two stations
- [ ] B2. Search for other trains (Z / K / T types) — usually a separate
      tab or toggle on the search page
- [ ] B3. Search the same route but for a different date
- [ ] B4. Search a route you expect to have nothing on it
- [ ] B5. Open the ticket/trip detail view for one result
- [ ] B6. Search using a station name that does not exist

Note in your log which station pairs you used. If B1 returns nothing at
all, tell Shaafi immediately before continuing — that is a blocker, not a
normal result.

### Section C — Contacts (3 actions)

- [ ] C1. Open the contacts page and view the list
- [ ] C2. Add a new contact (name starting with `sweep_`)
- [ ] C3. Delete the contact you just added

### Section D — Booking and paying (7 actions)

Each booking creates an order you will use in Section E, so do not skip
these.

- [ ] D1. Start a booking from a search result
- [ ] D2. Complete a plain booking — no insurance, no food, no shipping
- [ ] D3. Complete a second booking **with insurance/assurance selected**
- [ ] D4. Complete a third booking **with a food order selected**
- [ ] D5. Complete a fourth booking **with consign / shipping details**
- [ ] D6. Pay for one of the orders
- [ ] D7. Pay for a second order

Log the order number for each booking if the site shows one. It makes the
traces far easier to line up afterwards.

### Section E — Order management (6 actions)

- [ ] E1. View your order list
- [ ] E2. Open the detail view of one order
- [ ] E3. Cancel one of your unpaid orders
- [ ] E4. Change or rebook one of your paid orders to a different trip
- [ ] E5. Collect the ticket for a paid order
- [ ] E6. Enter the station / check in for a collected ticket

### Section F — Other user features (3 actions)

- [ ] F1. Open the consign / shipping list
- [ ] F2. Look up a consign price
- [ ] F3. Request a voucher or receipt for a paid order

### Section G — Admin panel (11 actions)

- [ ] G0. Log out, then log in as `admin` / `222222`

Everything below is **view only** except G3.

- [ ] G1. Admin: view the station list
- [ ] G2. Admin: view the train type list
- [ ] G3. Admin: add a station named `sweep_teststation`
- [ ] G4. Admin: view the route list
- [ ] G5. Admin: view the trip / travel list
- [ ] G6. Admin: switch to the second trip list if there are two
      (one covers G/D trains, the other covers Z/K/T)
- [ ] G7. Admin: view the order list
- [ ] G8. Admin: view the second order list if there are two
- [ ] G9. Admin: view the user list
- [ ] G10. Admin: view the config list
- [ ] G11. Admin: view the price list
- [ ] G12. Admin: view the contacts list

Do not delete `sweep_teststation`. Shaafi will clean it up.

### Section H — Anything else

- [ ] H1. Click into any menu, page, or button you have not touched yet
- [ ] H2. Log each one the same way

Spend the last fifteen minutes here. Anything you find that is not on this
list is exactly the coverage we are missing.

---

## Part 4 — Finishing up

### 4.1 Close out the log

- [ ] In the terminal, type `done` and press Enter
- [ ] It prints a summary block. **Copy that block** — you will paste it
      into your message

### 4.2 Export the browser recording

**Chrome or Edge:**
- [ ] In DevTools, on the Network tab, click the download / export icon
      (a downward arrow near the top of the request list)
- [ ] Choose **Export HAR (sanitized)** if you are offered a choice —
      sanitized strips out cookies and auth headers, which is what we want
- [ ] Save it as `coverage_sweep.har`

**Firefox:**
- [ ] Right-click anywhere in the request list
- [ ] Choose **Save All As HAR**
- [ ] Save it as `coverage_sweep.har`

The file may be 10 to 100 MB. That is normal.

### 4.3 Send Shaafi three things

- [ ] `coverage_sweep_session_log.txt` (created next to `session_log.py`)
- [ ] `coverage_sweep.har`
- [ ] A message containing:
  - the summary block the script printed
  - your time.is result from step 1.2
  - which station pairs you searched in Section B
  - anything that surprised you

- [ ] Tell him the session is over so he can start the extraction

**Send it the same day.** The backend holds traces in memory. If the system
restarts before he extracts, everything you did is gone and the session
has to be repeated.

---

## If something goes wrong

**The site stops responding entirely.** Stop clicking. Log a `note`. Message
Shaafi. Do not refresh repeatedly — that looks like an attack in the data.

**You closed DevTools by accident.** The HAR is lost from that point on.
Reopen it, tick Preserve log again, log a `note` saying when it happened.
The written log still covers you.

**You closed the terminal by accident.** Nothing is lost — every line is
written to the file immediately. Just start it again; it appends to the
same file and marks the resume point.

**You lost track of where you were.** Look at the last few lines of
`coverage_sweep_session_log.txt` and carry on from there.

**You are running out of time.** Sections A, B, D, E, and G matter most.
Skip C and F before you skip those. Log where you stopped.

---

## Quick reference

| | |
|---|---|
| Site | http://<research-host>:32677/ |
| User | `fdse_microservice` / `111111` |
| Admin | `admin` / `222222` |
| Never use | `admin` / `admin` |
| Gap between actions | 20–30 seconds |
| Max retries on failure | 1 |
| Admin: create prefix | `sweep_` |
| Admin: delete | never, unless you made it |
| Logger commands | description · `ok` · `fail <why>` · `note <what>` · `done` |
