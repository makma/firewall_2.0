# Firewall 2.0: Account Takeover Protection at the Edge

## Introduction

The traditional understanding of firewalls is outdated. Conditional decision-making based on static data points such as IP addresses, script tags, query analysis, ASN detection, and other similar methods still have value, but they fall short in today’s web environment. Modern web technologies allow us to extend firewall protection beyond the old-fashioned `IF IP=X THEN 403` approach.

---

## Firewall 1.0 vs. Firewall 2.0

### 1. Firewall 1.0: Fingerprint Data as a Trigger for WAF Rules

The traditional approach to firewall security—**Firewall 1.0**—involves consuming Fingerprint data on the server, lambda function, or worker. This method leverages standard WAF (Web Application Firewall) APIs to create and enforce rules. Here's how it works:

- When specific data points from Fingerprint are recognized as malicious or suspicious based on the business's preferences, a firewall rule is created.
- This rule is then deployed using the platform's WAF API (for example, blocking requests from a specific IP address or ASN).
- The firewall rules are responsible for blocking future malicious requests at the WAF level.

**Requirements:**
- A platform that supports lambdas, workers, or origin server-based logic.
- A WAF with an API that allows dynamic rule creation.

This approach still relies on the platform's ability to enforce firewall rules at the server level, and while effective, it has limitations when dealing with sophisticated threats that can bypass static rule-based detection.

### 2. Firewall 2.0: A Modern, Independent Approach

**Firewall 2.0** offers an alternative (and complementary) method to the standard WAF-based approach. Rather than creating static WAF rules, all requests to the protected origin are proxied through a cybersecurity platform (e.g., Cloudflare Workers). Fingerprint data is assessed **at the proxy level**, meaning that malicious requests are intercepted **before** reaching the origin server.

- Fingerprint data is assessed dynamically in the worker or lambda, making a real-time decision on whether to forward the request to the origin server.
- If a request is flagged as malicious, it is not forwarded to the origin, and no firewall rules need to be created.
- **Key advantage**: No request reaches the origin server, reducing the risk of fraud or attacks that could reach the server level.

In this model, the worker or lambda effectively acts as the first line of defense, preventing fraud before it even has a chance to interact with your backend infrastructure. This method is independent of the platform's WAF capabilities and does not require creating or maintaining firewall rules.

**Requirements:**
- A platform capable of proxying all requests to the origin server (such as Cloudflare or Akamai).
- The ability to hide the origin server's IP address, ensuring that all requests are assessed before they reach the origin.
- A worker or lambda function that can dynamically evaluate requests based on Fingerprint data before forwarding them.

By shifting decision-making to the edge, **Firewall 2.0** reduces the burden on backend infrastructure and enhances security by making dynamic, context-aware decisions based on real-time data.

---

This section contrasts the old and new approaches, highlighting how Firewall 2.0 brings more flexibility and real-time decision-making to request handling. Let me know if you'd like further adjustments!

### Solution

This guide demonstrates how to implement account takeover protection using a modern firewall solution—before traffic even reaches your origin server. At the edge, we will utilize device intelligence data provided by [Fingerprint](https://fingerprint.com), enabling dynamic decisions such as blocking, flagging, logging, or challenging requests based on browser and environment analysis. Rather than relying on static IP-based rules (or similar), this method adapts in real-time based on dynamic context.

While this guide focuses on account takeover protection, these principles are broadly applicable to other sensitive actions, such as:

- Viewing sensitive data
- Transferring money or assets
- Approving bonuses or loans
- Scraping detection/prevention
- ...

The implementation discussed here uses [Cloudflare Workers](https://workers.cloudflare.com/), but the concepts are platform-agnostic and can be applied to any system capable of proxying requests to origin servers.

### Limitations

Traditional firewalls typically work using static HTTP request contexts, analyzing headers, body content, and other data from the first client-server interaction. However, since Fingerprint collects intelligence from the client-side JavaScript context, this solution requires device intelligence to be executed in the browser first. Therefore, it is **not suitable for protecting the first page load** of a session.

While it is possible to introduce a splash screen as a workaround, doing so can negatively affect user experience in some cases. These guidelines do not cover first-page load protection.

### Expectations

This guide and the accompanying code are **not production-ready** and do not represent an officially supported integration. The examples here describe general principles for building a firewall based on device and browser intelligence. You will need to adapt the code to meet your organization’s specific guidelines, requirements, and business needs.

**Note:** This example uses [sealed client results](https://dev.fingerprint.com/docs/sealed-client-results) for optimal performance. While using webhooks or server APIs is possible, doing so would require significant changes to the Cloudflare worker code.

---

## Prerequisites

Before proceeding, ensure the following:

- You have a **Fingerprint** account and have integrated device intelligence collection on your frontend.
- Your backend origin is **[proxied through Cloudflare](https://developers.cloudflare.com/dns/manage-dns-records/reference/proxied-dns-records/)**.
  
For this guide, we will demonstrate using sealed client results. If you'd like to use webhooks or the Server API, substantial adjustments will be necessary.

---

## Steps

### 1. Collect Fingerprint Data on the Frontend

Start by collecting Fingerprint data on the frontend. Ensure that this data is gathered **immediately before** the login request is sent, alongside the user credentials. This helps to protect against replay attacks.

For more details on replay attack prevention, review the documentation here: [Protecting from Client-Side Tampering](https://dev.fingerprint.com/docs/protecting-from-client-side-tampering).

### 2. Create a Cloudflare Worker

Next, create a Cloudflare Worker based on the code in this repository. The worker unseals the Fingerprint data and uses it to make sample decisions (e.g., blocking or allowing requests). You will need to modify this worker to meet your business needs, including custom decision logic, logging, and challenges.

#### Example Customizations
You might want to:

- **Block suspicious requests** before they hit your origin server.
- **Log events** for analysis.
- **Challenge requests** for additional verification.
- **Cross-check additional data sources**, such as known malicious visitors, smart signals, or trusted visitor IDs.

If you prefer not to use sealed client results, you can use webhooks or the Server API for event data.

### 3. Register a Route Binding

[Register a route binding](https://developers.cloudflare.com/workers/configuration/routing/routes/) that matches the endpoint for your login route. This effectively places the Cloudflare worker between your frontend and origin server. Each incoming request is processed by the worker before reaching the origin, allowing it to enforce your security rules.

---

## Demo

A sample demo has been deployed to showcase this capability:

- **Frontend code**: [Login UI](https://experiments.martinmakarsky.com/login)
- **Origin login logic**: [Login Route](https://github.com/makma/experiments.martinmakarsky.com/blob/main/next-app/app/api/login/route.ts)
- **Worker code**: [Cloudflare Worker Code](/worker.js)

### Demo Walkthrough

When the user submits their credentials on the login page, Fingerprint data is collected and sent with the credentials to the origin server at the `/api/login` endpoint in the following format:

```
{
  "username": "user",
  "password": "pw",
  "fingerprintData": {
    "requestId": "redacted",
    "sealedResult": "redacted",
    "visitorId": "",
    "visitorFound": false,
    "meta": {
      "version": "v1.1.2814+a53d61ebf"
    },
    "confidence": {
      "score": 0
    }
  }
}
```

Since the Cloudflare worker is registered for the `/api/login` route, it intercepts the request before it reaches the origin server. In this example, the server-side login logic is simplified: if the password is `pw`, a 200 response is returned; otherwise, a 401 is issued.

#### Intercepting Malicious Requests

For example, if you use the TOR browser and submit valid credentials, the worker will block the request based on the following rule:

```js
...
check: (data) => data.products.suspectScore.data.result > 10,
message: "Suspect score!",
status: 403,
...
for (const rule of rules) {
    if (rule.check(fingerprintData)) {
        return new Response(rule.message, { status: rule.status });
    }
}
```

In this case, a 403 response is returned, proving that the worker stopped the request before it reached the origin server.

---

## Conclusion

This guide outlines how to build a modern firewall solution leveraging real-time device and browser intelligence to protect sensitive actions, such as logins, from account takeover attempts. By positioning security decisions at the edge, you can filter out malicious traffic before it even reaches your backend infrastructure.

For further customizations, please adapt the provided code to fit your specific use case.
