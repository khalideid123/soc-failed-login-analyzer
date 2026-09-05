# SOC Investigation Notes

## Alert summary

The authentication dataset was reviewed for repeated failed login attempts originating from the same source IP.

One source generated enough failed login attempts to exceed the detection threshold. A successful authentication was then observed from that same source.

## Analyst assessment

Repeated failures occurring within a short sequence can be consistent with:

- Brute-force attempts
- Password spraying
- A user repeatedly entering an incorrect password
- Automated login activity

A later successful authentication increases the importance of the event because the account may have been accessed after repeated guessing attempts.

The pattern alone does **not** prove compromise. In a real SOC, additional evidence would be required.

## Recommended next steps

1. Review the affected account's recent authentication history.
2. Check whether the source IP is expected for the user.
3. Review endpoint and identity-provider logs.
4. Look for MFA challenges or unusual device activity.
5. Confirm whether the user recognizes the login.
6. Reset credentials or revoke sessions if compromise is confirmed.

## Detection rule

Generate an alert when a source IP produces five or more failed login attempts.

- **Medium:** threshold reached with no later success.
- **High:** threshold reached and a successful authentication is observed after failures.

## Interview explanation

> I built a Python-based authentication log analyzer that groups failed logins by source IP, applies a configurable detection threshold, and raises higher-severity alerts when a successful login follows repeated failures. I also documented the investigation and response steps a SOC analyst would take.
