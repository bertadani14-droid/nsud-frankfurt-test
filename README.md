# NS SR Frankfurt connectivity diagnostic

Minimal Node.js application for a one-time HTTPS test on Render. It checks **fixed official public URLs only** and stores their response status or network error in memory. It is **not an HTTP proxy** and does not access private or user data.

## Setup in Render
1. Create a **public** GitHub repository and upload `server.js` and `package.json` to its root (README optional).
2. In Render choose **New Web Service > Public Git Repository**, paste the repository URL, and choose **Connect**.
3. Set **Name** `nsud-frankfurt-test`, **Language/Runtime** Node, **Region** Frankfurt, **Branch** main, **Build Command** `npm install`, **Start Command** `npm start`, **Instance Type** Free. Do not select a paid instance or add a card.
4. After deploy visit the onrender.com URL. The JSON's `status` becomes `completed` after the initial five checks. Refresh if it still says `running`.

## Tests
- NSSR_HTTPS_HOME: https://www.nsud.sk/
- NSSR_OPENDATA: https://www.nsud.sk/ws/opendata.php?getDecision&id=124230
- NSSR_F018_PDF: https://www.nsud.sk/data/att/659/873803.b15efc.pdf
- NSSR_HTTP_CONTROL: http://www.nsud.sk/
- JUSTICE_HTTPS_CONTROL: https://www.justice.gov.sk/

Success is **not** automatically claimed: inspect each `status_code` or `connection_error`. An HTTP 403 or 404 still proves an HTTP response arrived, unlike an early connection exception. The program does not follow redirects, parse PDFs or retrieve documents in full. This is not a production bridge for the legal research system.

The free Render service may sleep after inactivity and then restart. A restart runs the tests again. Delete the service after evaluating the report if no longer needed.
