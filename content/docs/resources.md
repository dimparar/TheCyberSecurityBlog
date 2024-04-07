+++
title = 'Resources'
date = 2024-04-07T23:40:09+03:00
draft = false
showpage = true
+++

# HTTPS Encryption & Remote Banking Authentication Attacks
This article discusses the secure HTTPS Protocol intended for web-resources and its principles of operation as well as its strengths and weaknesses. It explains how attacks on HTTPS may lead to traffic being decrypted, particularly in systems for remote banking services and personal logins to web-resources.

Web resources, such as remote banking services, web portals for private offices, e-mail, instant messaging and VoIP-telephony require protocols for secure data exchange. This ensures the privacy of [personal customer data](https://en.wikipedia.org/wiki/Personally_identifiable_information) and protection from tampering of the data exchanged between an Internet server and the user's electronic device. One of the most common and well-known application protocols for web-resources is [HTTPS](https://en.wikipedia.org/wiki/HTTPS). The HTTPS protocol is essentially the implementation of the standard for Internet protocol [HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol) using encryption. Asymmetric encryption such as [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) algorithms or Diffie-Hellman for authentication is used by systems, which utilize public and private keys to secure data.

**The HTTPS Protocol**
----------------------

In the past, all data in HTTPS was encapsulated and sent over [SSL and TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) cryptographic protocols. Today, only TSL Protocol is used because a critical vulnerability called [Heartbleed (CVE-2014-0160)](https://en.wikipedia.org/wiki/Heartbleed) was found with SSL in 2014, which prevented it from being used in the future. The security of TSL sometimes remains in question. For example, there have been vulnerabilities in the past relevant to open source clients like [OpenSSL](https://en.wikipedia.org/wiki/OpenSSL) allowing the attack [FREAK — TLS Downgrade](http://www.eweek.com/security/freak-attacks-ssltls-security-putting-apple-android-users-at-risk.html). After those vulnerabilities were discovered, developers released patches to fix them.

Despite some vulnerabilities (which every system has), HTTPS remains a very commonly used security protocol on the Internet. It is used to authenticate web-resources requiring login to personal accounts and is often used with remote banking services. It primarily defends against attacks such as [man-in-the-middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) and active [sniffing](https://en.wikipedia.org/wiki/Packet_analyzer) /packet analyzing of traffic using specialized hacking software. Relying on HTTPS is not infallible because hackers can still attempt to decrypt intercepted traffic that is transmitted over HTTPS. However, this is not a vulnerability of the cryptographic algorithms used or the technical implementation of this protocol. Often, this type of breach can be traced back to an incorrect configuration of the operating environment and building the [chain of trust](https://en.wikipedia.org/wiki/Chain_of_trust) for the certificate and its [public keys](https://en.wikipedia.org/wiki/Public-key_cryptography).

**How Secure HTTPS Sessions Could Be Attacked**
-----------------------------------------------

The process to establish a secure HTTPS session is basically a four-step process:

1.  Through HTTPS, the user requests a secure session by sending a request to the server to set up a secure SSL session.
2.  The web-server responds by sending its certificate to the user’s browser where the certificate will be checked for validity and whether it is “signed” by "someone" that is trusted.
3.  The browser responds by sending a one-time encryption key for the session that has been encrypted by using the public key supplied by the web-server.
4.  The web-server then decrypts the session key with its private key, thus establishing a secure session between the two.

[![ENCRYPTION HTTPS: ATTACK ON AUTHENTICATION IN REMOTE BANKING SERVICES - A RUSSIAN PERSPECTIVE](https://www.cryptomathic.com/hs-fs/hubfs/Images_misc/Blog-Photos/Encryption-process-Cryptomathic.png?width=536&name=Encryption-process-Cryptomathic.png "ENCRYPTION HTTPS: ATTACK ON AUTHENTICATION IN REMOTE BANKING SERVICES - A RUSSIAN PERSPECTIVE")](https://www.cryptomathic.com/hubfs/Images_misc/Blog-Photos/Encryption-process-Cryptomathic.png)

It is possible to create such a certificate without going to a single CA. Under Unix\\Linux, tools such as _ssl-ca_ or _gensslcert_ (utility) can be used to create a certificate with two keys, which is called «self-signed».

Using this procedure, an attacker or legitimate network administrator could replace the original certificates from legitimate web resources with these self-signed certificates generated on the local proxy server, which is accessed by users the Internet. The administrator or the attacker:

*   Generates certificates for each user
*   [Forces group policies](https://kb.iu.edu/d/akls) in MS Active Directory
*   Loads certificates into the browser of each user

After this, the user’s computer will accept all certificates signed by any organizations that are trusted by the proxy server.

This scheme sniffs server traffic and is actually akin to a man-in-the-middle attack that is often used by hackers, on open Wi-Fi networks where the victim connects to an open and unsecured network in a public place, such as a café or subway. Alternatively, this tactic can be used by a network administrator to gain control of all network traffic by employees on a corporate network, similar to the same way a [DPL-system](https://en.wikipedia.org/wiki/Data_loss_prevention_software) would operate.

**Russia’s Response with Law of Yarovaya**
------------------------------------------

In 2016, Russia approved a federal law called the ["Law of Yarovaya.”](https://en.wikipedia.org/wiki/Yarovaya_Law) This law requires the transfer of encryption keys of all developers of all software and hardware products in the [Federal Security Service of Russia](https://en.wikipedia.org/wiki/Federal_Security_Service) (FSB). The intent of this law is that the FSB will have access to all systems and all traffic arising on the Internet to:

*   Ensure national security
*   Prevent terrorist acts
*   Investigate criminal acts

The need for such measures arose after terrorist [attacks in Paris](https://www.nytimes.com/news-event/attacks-in-paris) and [explosions at the airport in Brussels](https://en.wikipedia.org/wiki/2016_Brussels_bombings) when the confiscated iPhone of one of the terrorists was found to have encrypted content of communications between terrorists in preparing attacks.

Theoretically, by using the above-described method of attack on HTTPS, the FSB is able to access and decrypt all traffic that passes through encrypted channels. This would require large data centers and computing facilities. Many experts say that such action is a violation of the constitutional rights of citizens to privacy and secrecy of their communications. However, the FSB argued that this measure would be used only in a critical situation. This measure has already been legalized and put into effect in Kazakhstan during 2016.
