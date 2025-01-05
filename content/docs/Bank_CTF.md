+++
title = 'Bank CTF'
date = 2024-03-13T01:23:32+02:00
draft = false
showpage = true
+++

Link:[TryHackMe | Bank CTF](https://tryhackme.com/room/bankctf)

- service apache2 start -> start apache2 server
- service apache2 stop -> stop apache2 server

- wget -> download files from internet

<u>Web Crawler</u>
A web crawler, or spider, is **a type of bot that is typically operated by search engines like Google and Bing**. Their purpose is to index the content of websites all across the Internet so that those websites can appear in search engine results

<u>robots.txt</u>
It is a text file with instructions for bots (mostly [search engine crawlers](https://www.seobility.net/en/wiki/Search_Engine_Crawlers "Search Engine Crawlers")) trying to access a website. It defines which areas of the site crawlers are allowed or disallowed to access.
Public File (anyone can see it) -> go to main domain and add /robots.txt (ex. https://google.com/robots.txt)

<u>gobuster</u>
Record Scanner written in Go.
Attack to a internet application by enumerating hidden files and directories.
Alternative choice: **dirb**
**Advantages:** Gobuster is fast
**Disadvantages:** No recursive directory exploration, ex. for directories one level deep, another scan is going to be needed!
**Flags needed** -> dir -u <IP Address/Domain Name> -w \<wordlist\>
**Most Common Wordlist** -> /usr/share/wordlists/dirb/common.txt 


- dirb -> (link: ) Find hidden files and directories on a Web Server
- goBuster -> alternative to dirb
<u>dirb and goBuster can be traced</u>
