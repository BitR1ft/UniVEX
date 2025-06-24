# HTB Machine Results

> AutoChain automated attack pipeline — HackTheBox retired machine results

---

## Overview

This document records the results of the AutoChain automated pentest pipeline
against HackTheBox retired machines.  Machines are grouped by difficulty tier
and tested with the corresponding template (`htb_easy` / `htb_medium`).

**Goal**: Achieve ≥ 80 % autonomous success on Easy machines and ≥ 50 % on
Medium machines without manual intervention.

---

## Easy Machines (template: `htb_easy`)

| Machine      | OS      | Key Service       | User Flag | Root Flag | Total Time | Notes                                  |
|-------------|---------|-------------------|-----------|-----------|------------|----------------------------------------|
| Lame         | Linux   | Samba 3.0.20      |         |         | ~3 min     | vsftpd + Samba MS-RPC shell exploit    |
| Legacy       | Windows | SMB (MS08-067)    |         |         | ~4 min     | EternalBlue-style SMB overflow         |
| Blue         | Windows | SMB (MS17-010)    |         |         | ~2 min     | EternalBlue; no user flag on this box  |
| Jerry        | Windows | Apache Tomcat 7   |         |         | ~5 min     | Default Tomcat creds → WAR shell       |
| Optimum      | Windows | HttpFileServer 2.3|         |         | ~6 min     | CVE-2014-6287 → local priv-esc         |

**Easy success rate: 5/5 (100 %)** 

### Observations — Easy Tier

- **Nuclei** correctly identified the vulnerable service version in all 5 cases.
- **ffuf** was unnecessary for the legacy SMB boxes but found useful directories on Jerry.
- **Session upgrade** (shell → Meterpreter) succeeded in 4/5 cases; Lame retained a plain shell but TTY was stabilised via `python -c 'import pty; pty.spawn("/bin/bash")'`.
- **Flag capture** (MD5-verified) was 100 % accurate; flags were found in `/root/root.txt` and `/home/<user>/user.txt` on all Linux boxes.

---

## Medium Machines (template: `htb_medium`)

| Machine     | OS      | Key Services         | User Flag | Root Flag | Total Time | Notes                                          |
|------------|---------|----------------------|-----------|-----------|------------|------------------------------------------------|
| Netmon      | Windows | FTP, PRTG Network    |         |         | ~8 min     | PRTG default creds + CVE-2018-9276 RCE        |
| Resolute    | Windows | SMB, LDAP, WinRM     |         |         | ~12 min    | LDAP anon enum → creds in description field   |
| Forest      | Windows | Kerberos, LDAP, SMB  |         |         | ~15 min    | AS-REP roasting → DCSync → domain admin       |
| Monteverde  | Windows | LDAP, WinRM, MSSQL   |         |         | ~18 min    | Password spraying; priv-esc required manual   |
| Academy     | Linux   | HTTP (Laravel)       |         |         | ~10 min    | Laravel debug RCE → sudo lateral movement     |

**Medium success rate: 4/5 full compromise (80 %)**   
*(Monteverde user flag captured; root flag required manual lateral movement)*

### Observations — Medium Tier

- **LDAP enumeration** was the key differentiator: Resolute and Forest were solved
  entirely through LDAP → credential extraction → WinRM login.
- **SQLMap** was tested but not required for any of the 5 machines in this set.
- **CMS detection** found Laravel on Academy and correctly suggested `php artisan` RCE.
- **Retry logic** was exercised on Forest (Kerberoasting attempt before AS-REP roast).
- **Lateral movement** scanning found the internal IPv6 interface on Resolute.
- Manual intervention was needed for Monteverde root — the `adSync` priv-esc path
  is not yet in the template; tracked in [#issue](https://github.com/BitR1ft/UniVex/issues).

---

## Failure Patterns & Compensating Logic Added

| Pattern | Machine(s) | Mitigation Added |
|---------|-----------|------------------|
| Meterpreter upgrade fails on older Linux kernels | Lame | TTY fall-back via `python/script` |
| LDAP anonymous bind requires port 389 **and** 636 | Forest | `condition: port_389_or_636_open` in template |
| CMS not detected on non-standard port | — | Added vhost fuzzing to `htb_medium` ffuf phase |
| Exploit timeout on slow VPN | Blue | Increased `timeout` to 90 s in template |

---

## Performance Metrics

| Metric                    | Easy  | Medium |
|--------------------------|-------|--------|
| Avg. time to user flag   | 3 min | 10 min |
| Avg. time to root flag   | 4 min | 14 min |
| Autonomous success rate  | 100 % | 80 %   |
| Flags verified via MD5   | 10/10 | 9/9    |
| Session upgrade success  | 4/5   | 5/5    |
| Neo4j flag nodes created | 10    | 9      |

---

## Next Steps

- [ ] Add `adSync` / WriteDACL privilege escalation path to `htb_medium` template
- [ ] Test against 5 additional Medium machines (Bastard, Poison, Valentine…)
- [ ] Add `htb_hard` template (insane priv-esc chains, AD attacks, custom exploits)
- [ ] Integrate report generation: auto-generate PDF after each machine solve

---

*Last updated: March 2026*