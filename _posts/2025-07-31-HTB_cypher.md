---
title: HTB Cypher
date: 2025-07-31
tags: [Linux, HTB, Neo4j, cypher injection, bbot]
categories: HTB
difficulty: Medium
points: 40
image:
  path: /assets/img/posts/cypher/HTB_cypher_cover.png
  alt: HTB Cypher Preview
  width: 300px
  height: 200px
  class: right
pin: false
toc: true
comments: true

---

> **OS:** 🐧 Linux  
> **Difficulty:** <span style="color:goldenrod; font-weight:600;">Medium</span>  
> **Points:** 40  
> **Author:** Techromancer

Cypher is a medium Linux machine focused on a cypher injection flaw to bypass login. This leads to a custom web app where fuzzing reveals a Java file with command injection, granting a shell as neo4j. A history file leaks credentials for graphasm, who can run bbot as root. Privilege escalation is achieved by abusing a custom bbot module to execute arbitrary commands.

---

## Foothold

<!-- Continue the writeup here -->
