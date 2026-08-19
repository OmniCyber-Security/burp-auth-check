package com.omnicybersecurity.authcheck.ui;

import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;

/** In-product reference for the script API and the verdicts. */
public final class HelpPanel extends JPanel {

    public HelpPanel(boolean dark) {
        super(new BorderLayout());
        JEditorPane pane = new JEditorPane("text/html", html());
        pane.setEditable(false);
        pane.setCaretPosition(0);

        HTMLEditorKit kit = new HTMLEditorKit();
        StyleSheet styles = kit.getStyleSheet();
        String text = dark ? "#dddddd" : "#111111";
        String code = dark ? "#1e1e1e" : "#f4f4f4";
        String accent = dark ? "#7fb3ff" : "#12429c";
        styles.addRule("body { font-family: sans-serif; font-size: 10px; color: " + text + "; margin: 12px; }");
        styles.addRule("h2 { color: " + accent + "; font-size: 13px; margin-top: 18px; }");
        styles.addRule("h3 { font-size: 11px; margin-top: 14px; margin-bottom: 4px; }");
        styles.addRule("code, pre { font-family: monospace; background-color: " + code + "; }");
        styles.addRule("pre { padding: 8px; }");
        styles.addRule("td { padding: 2px 10px 2px 0; vertical-align: top; }");
        pane.setEditorKit(kit);
        pane.setText(html());
        pane.setCaretPosition(0);
        pane.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        if (dark) {
            pane.setBackground(new Color(43, 43, 43));
        }

        add(UiUtils.scroll(pane), BorderLayout.CENTER);
    }

    private static String html() {
        return """
                <html><body>
                <h2>What this extension does</h2>
                <p>It takes a request that <i>worked</i> for one user and re-sends it as everybody else you have
                configured, plus once with no credentials at all. If another user's replay comes back with the same
                successful response, that user reached data they should not have, and the row is flagged
                <b>Bypassed</b>.</p>

                <h3>Getting started</h3>
                <ol>
                  <li><b>Identities</b> tab: add one identity per user. Put their login details in the credential
                      table -- these are saved in the Burp project.</li>
                  <li>Write an auth script for each identity, or just set a static <code>Authorization</code> header
                      under <b>Request rewriting</b>. Press <b>Test authentication now</b> to prove it works.</li>
                  <li>Browse the application as your <i>most privileged</i> user, or the user who owns the data. That
                      traffic becomes the baseline.</li>
                  <li>Turn on <b>Auto-test in-scope traffic</b> in the Results tab, or right-click a request anywhere
                      in Burp and choose <b>Send to Auth Check</b>.</li>
                </ol>

                <h2>Auth scripts</h2>
                <p>Scripts are Groovy. They run whenever a session is needed and whenever one dies. The last
                expression (or an explicit <code>return</code>) is the auth material to apply to every replay.</p>

                <h3>What you get handed</h3>
                <table>
                  <tr><td><code>creds</code></td>
                      <td>Map of this identity's credential variables, e.g. <code>creds.username</code>.</td></tr>
                  <tr><td><code>http</code></td>
                      <td>HTTP helper -- see below. Requests go through Burp, so they appear in the Logger.</td></tr>
                  <tr><td><code>vars</code></td>
                      <td>Mutable map that <b>survives between refreshes</b>. Stash refresh tokens here.</td></tr>
                  <tr><td><code>log</code></td>
                      <td><code>log.info</code>, <code>log.warn</code>, <code>log.error</code>. Shown under the
                          script and in Burp's extension output.</td></tr>
                  <tr><td><code>api</code></td>
                      <td>The full Montoya <code>MontoyaApi</code>, for anything the helper does not cover.</td></tr>
                  <tr><td><code>identity</code></td><td>This identity's name, as a string.</td></tr>
                </table>

                <h3>The <code>http</code> helper</h3>
                <table>
                  <tr><td><code>http.get(url)</code></td><td>GET, optionally with a header map as a 2nd argument.</td></tr>
                  <tr><td><code>http.postJson(url, map)</code></td><td>POST JSON; maps and lists are serialised for you.</td></tr>
                  <tr><td><code>http.postForm(url, map)</code></td><td>POST a URL-encoded form; values are encoded.</td></tr>
                  <tr><td><code>http.post(url, body, contentType)</code></td><td>POST anything else.</td></tr>
                  <tr><td><code>http.send(request)</code></td><td>Send a Montoya <code>HttpRequest</code> you built yourself.</td></tr>
                  <tr><td><code>http.status(resp)</code></td><td>Status code as a number.</td></tr>
                  <tr><td><code>http.body(resp)</code></td><td>Response body as a string.</td></tr>
                  <tr><td><code>http.json(resp)</code></td><td>Parse the body into maps and lists.</td></tr>
                  <tr><td><code>http.cookie(resp, name)</code></td><td>One <code>Set-Cookie</code> value.</td></tr>
                  <tr><td><code>http.cookies(resp)</code></td><td>All cookies the response set, as a map.</td></tr>
                  <tr><td><code>http.header(resp, name)</code></td><td>One response header value.</td></tr>
                  <tr><td><code>http.extractFrom(resp, regex)</code></td><td>First capture group from the body.</td></tr>
                </table>
                <p>Redirects are never followed unless you ask, so a <code>Set-Cookie</code> on a 302 is still
                visible. Pass <code>true</code> as the last argument of <code>http.send</code> when a flow really
                needs the redirect followed. The "follow redirects when replaying" setting applies only to the
                request under test, not to your scripts.</p>

                <h3>What to return</h3>
                <pre>// bearer token
                return [headers: ['Authorization': "Bearer $token"]]

                // session cookie
                return [cookies: ['JSESSIONID': session]]

                // several things at once
                return [
                    headers: ['Authorization': "Bearer $token", 'X-Tenant': creds.tenant],
                    cookies: ['csrf': csrfCookie],
                    params : [[type: 'BODY', name: 'csrf_token', value: csrf]],
                    remove : ['If-None-Match']
                ]

                // a bare string goes into the identity's token header
                return "Bearer $token"</pre>
                <p><b>Cookies must be wrapped in <code>cookies:</code>.</b> A bare map is applied as
                <i>headers</i> -- which is exactly the shape <code>http.cookies(resp)</code> returns, so
                <code>return http.cookies(resp)</code> quietly sets a header named <code>JSESSIONID</code> and the
                replays go out with no cookie at all. Write <code>return [cookies: http.cookies(resp)]</code>. The
                script log warns whenever a bare map is applied as headers.</p>
                <p>Throw an exception to signal failure -- the message lands on the identity's status line and the
                affected rows read <b>Auth failed</b> rather than pretending the test ran.</p>
                <p>Everything a script sends is recorded on the identity's <b>Login traffic</b> tab: the exact
                requests and responses of the last login, kept in the project. It is the quickest way to see why a
                login is failing, and it is what makes a finding reproducible later.</p>

                <h2>Sessions that die quickly</h2>
                <p>Three mechanisms, configured per identity on the <b>Session lifetime</b> tab:</p>
                <ul>
                  <li><b>Session lifetime</b> -- if the app expires sessions on a timer, state it. A background
                      task re-runs the script at 80% of that age, so replays never race the expiry.</li>
                  <li><b>Invalid-session pattern</b> -- a regex that appears when the session is gone
                      (<code>"error":"token_expired"</code>, <code>Please log in again</code>). This is the reliable
                      signal: on a match the session is rebuilt and the request replayed once, automatically.</li>
                  <li><b>Session-check URL</b> -- a cheap authenticated endpoint. A 401/403 is also the
                      <i>correct</i> result of a passing authorisation check, so it is never treated as expiry on its
                      own; this URL is probed to settle which it was. Without one, a speculative re-auth is allowed
                      at most once every 10 seconds, so a run of denials cannot cause a login storm.</li>
                </ul>
                <p>The same scripts are also published as Burp <b>session-handling actions</b>
                ("Auth Check: authenticate as ..."). Add one to a session-handling rule in project options and
                Scanner, Intruder and Repeater get live credentials too.</p>

                <h3>Keeping the noise down</h3>
                <p>Settings lets you drop traffic before it costs a replay: out-of-scope URLs, static resources,
                uninteresting baseline statuses, URL patterns, and <b>HTTP methods</b>. <code>OPTIONS</code> is
                filtered by default -- a CORS preflight carries no authorisation decision, and testing one per
                request would triple the traffic for nothing. Filtered traffic never appears in the results;
                "Send to Auth Check" ignores every filter.</p>

                <h2>Reading the verdicts</h2>
                <table>
                  <tr><td><b>Bypassed</b></td>
                      <td>Same status and near-identical body to the baseline: this identity reached the resource.
                          The finding to investigate.</td></tr>
                  <tr><td><b>Enforced</b></td>
                      <td>The server refused -- a denied status code, a denial pattern in the body, or a redirect to
                          login. Authorisation is working.</td></tr>
                  <tr><td><b>Review</b></td>
                      <td>Different from the baseline but not a recognisable denial. Usually the identity's own data,
                          sometimes a partial leak. Read it.</td></tr>
                  <tr><td><b>Auth failed</b></td>
                      <td>No session could be established, so nothing was proven. Fix the script first.</td></tr>
                  <tr><td><b>Error</b></td>
                      <td>The replay itself failed -- connection refused, timeout.</td></tr>
                </table>

                <h3>Two things that cause false positives</h3>
                <ul>
                  <li><b>A public endpoint.</b> If the unauthenticated replay also succeeds, everything else
                      "bypassing" it is expected. Those rows are annotated <i>endpoint appears public</i>, and the
                      unauthenticated column makes it obvious -- which is why leaving that replay on is worthwhile.</li>
                  <li><b>A baseline that was not a success.</b> Comparing against a 404 or a 500 proves nothing, so
                      those rows degrade to <b>Review</b> and say so instead of claiming a bypass.</li>
                </ul>
                <p>Body comparison deliberately does <i>not</i> normalise ids or numbers. Two users' own records have
                the same structure, and masking the values would make them look identical.</p>

                <h2>What is stored in the project</h2>
                <p>Everything lives in the <b>Burp project file</b>, so reopening the project restores the evidence
                as well as the setup:</p>
                <ul>
                  <li>Identities, their credential variables and their auth scripts</li>
                  <li>Settings -- filters, thresholds, denial rules</li>
                  <li><b>Every tested request and response</b> -- the baseline plus each identity's replay, with its
                      verdict, explanation and similarity score</li>
                  <li><b>The login traffic</b> each auth script generated, kept against the identity next to the
                      script that produced it (see the <b>Login traffic</b> tab)</li>
                </ul>
                <p>That combination is the point: months later a disputed finding can be reconstructed from the
                project alone -- the script, the credentials it read, the login exchange that minted the session,
                the replay that used it, and the baseline it was judged against.</p>
                <p>Storage is capped (Settings &rarr; Storing results in the project). You can store only rows worth
                revisiting, lower the cap, or turn storage off entirely. <b>Clear</b> on the Results tab wipes stored
                results too.</p>
                <p>Nothing is <b>encrypted</b>. The project now holds credentials, live session tokens in the stored
                login traffic, and response bodies from the application -- treat it as sensitive material and prefer
                dedicated test accounts.</p>
                </body></html>
                """;
    }
}
