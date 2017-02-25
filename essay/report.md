---
title: Cyber Security Coursework - Essay
author: James Donohue - <james.donohue@bbc.co.uk>
---

# Introduction

The paper to be evaluated is 'Web Application Firewalls: Enterprise Techniques' by Jason Pubal [-@pubal], as published on the SANS Institute Reading Room.

# Executive Summary of Paper

The domain of the paper is the use of a Web Application Firewall (WAF) to monitor network traffic to a web application for the purpose of preventing malicious activity. WAFs represent a relatively new category of security product specifically designed to apply rule sets to HTTP or HTTPS traffic, including those designed to prevent common web application vulnerabilities such as SQL injection or cross-site scripting (XSS) [@conklin].

The paper starts by describing the recent historial context of network-based attacks and firewalls, with a rise both in the prevalence of web applications and the quantity of attacks directed against them, reportedly accounting for 35% of data breaches in 2014. The author suggests that organisations can help to manage the risks associated with Internet-facing web applicatons by using a WAF both to block malicious traffic and also to perform 'virtual patching' when a vulnerability is discovered, in order to reduce remediation time.

The author reports that WAFs provide increased visibility of application traffic compared to a network firewall or IDS, and are therefore capable of preventing application-level attacks that network firewalls cannot, without requiring any modification to the web application itself. They achieve this by examining HTTP requests and comparing them to attack 'signatures', either blocking such attacks or raising alerts. Positive and negative security models are contrasted, defined as whether the WAF rules define what is allowed (whitelisting) or what is disallowed (blacklisting). These two models are analogous to the possible default policies of a packet filtering firewall, 'discard' or 'forward' [@stallings]. The author suggests that WAFs using negative security models are both easier to set up and have a lower configuration maintenance burden than those using positive models, but are not able to protect against unknown attacks and therefore less secure.

The paper then describes various approaches to deploying a WAF in a network environment (section 1.3). In a 'Reverse Proxy' configuration the WAF sits inline between the web server being protected and the network's external firewall, intercepting and proxying requests to the server, with rule sets applied. In a 'Layer 2 Bridge' deployment, the WAF is also inline but operates at a lower network layer, blocking traffic as required by simply dropping packets. In 'Out-of-Band' mode, rather than being inline the WAF receives a copy of network traffic which it monitors passively, interrupting malicious connections by sending TCP reset packets. The 'Server Resident' configuration means that WAF software is installed on the web server itself, removing the additional point of failure of a separate network device. Finally, 'Internet Hosted/Cloud' deployments rely on software as a service (SaaS) from a third-party cloud provider, with the WAF conceptually inline, similar to the 'Reverse Proxy' option.

In the next section (1.4) the paper covers in detail the main drivers (motivations) behind the use of WAFs in organisational contexts. The benefit given for 'production' applications, even those developed using a secure software development lifecycle (SDLC) is that the time and cost of remedying security issues that are identified after the application is live can be reduced. This benefit is shown as particularly relevant both to legacy applications that were developed in house and commercial off-the-shelf (COTS) software, where the organisation's ability to address underlying security issues in code may be restricted due to loss of relevant development skills or lack of vendor cooperation. The author next situates this approach as part of the vulnerability management process, specifically the need to 'shield' a vulnerable application from attacks while the affected code is fixed or updated, describing the technique as 'virtual patching'. The accuracy of a WAF is said to increase if it can import results from a dynamic application security testing (DAST) tool.

The need to ensure compliance, such as with the Payment Card Industry Data Security Standard (PCI DSS) for organisations that need to handle payment card information, is given as another significant driver of WAF usage. The PCI DSS requirement to review web applications using vulnerability assessment tools after any changes, and the high fines for which such organisations are liable, are given as reasons for using WAFs as an alternative way of achieving compliance. Next the paper describes the role of WAFs as sensors within a larger intrusion detection system. Data from a WAF can be sent to an organisation's security incident and event management (SIEM) system for correlation with other data, which the author says expands such a system's capabilities into the area of detecting attacks against the organisation's web properties. A brief depiction of major WAF vendors at the time of writing is then given.

The rest of the paper describes a lab environment created by the author to demonstrate how a WAF can be used to support virtual patching and security monitoring. The open-source ModSecurity WAF is installed on the same Linux-based virtual machine as a PHP/MySQL web application specially designed to exhibit common security vulernabilities as a teaching aid, the Damn Vulnerable Web App (DVWA). This illustrates the Server Resident model described earlier, although it is stated that ModSecurity also supports the Reverse Proxy approach. The OWASP Cole Rule Set (CRS) is imported into ModSecurity for illustration.

On a separate virtual Linux server, the log management tool AuditConsole is installed to illustrate the aggregation of audit logs from potentially multiple instances of ModSecurity. This platform offers tools for creating notifications based on events or performing further analysis.

Lastly a Windows host is provisioned running a DAST tool for identifying web application vulnerabilities called Burp Suite, and another tool called ThreadFix that can aggregate results from various security testing tools including Burp Suite and use them to generate WAF rules, which ModSecurity can then import.

The author then discusses virtual patching in more detail, describing the vulnerability management process and the possibility of using a WAF to fix web application vulnerabilies without changing the application's source code. This is because the WAF is able to intercept and prevent attacks that match a particular rule. The paper illustrates this with the example of an (intentional) XSS vulnerability in DVWA. Using Dynamic Application Security Testing (DAST) such vulnerabilities can be identified by 'spidering' the web application and recursively checking for security issues. In the lab, Burp Suite was used to test DVWA and identified the XSS vulnerability above. The Burp Suite results were imported into ThreadFix as an example of aggregating findings from multiple tools and web applications. ThreadFix then generates WAF rules corresponding to the vulnerability, which are deployed to ModSecurity. Following installation, the XSS vulnerability is manually re-tested and is blocked by the WAF. The author points out that although the advantage of this approach is the speed with which the attack surface can be reduced, it may not always be possible to remediate the vulnerability entirely in this way, and therefore virtual patching should only be viewed as temporary risk reduction.

In the next part of the lab, the author describes the concept of Network Security Monitoring (NSM) and its assumption that security breaches are inevitable. This approach shifts the goal to detecting and reacting appropriately to incidents. This approach is broken down into three phases: collection, in which sensors (which may be WAFs among other types) collect data for analysis, detection, in which collected data is examined and alerts generated, and analysis, when a human interprets the data produced and takes action as necessary. The paper states that the importance of WAFs are sensors within an NSM infrastructure depends on how critical web applications are to the organisation's goals. WAFs are shown to be particularly effective where inbound network traffic must be decrypted before inspection.

The lab demonstrates the use of ModSecurity as an NSM sensor sending logs and alert data to the AuditConsole management tool. The AuditConsole dashboard shows alerts produced via ModSecurity owing to the OWASP CRS as a result of the scan performed by the Burp Suite DAST.

In conclusion, the author re-emphasises the importance of web applications today and re-states that virtual patching can quickly reduce risk cause by vulnerabilities in production web applications, and may be the only option available for legacy or COTS applications. The author suggests that WAFs have visibility into application traffic that no other monitoring tool is capable of. Finally the author points out the specialist skill set required for application security monitoring as opposed to 'general' network monitoring, and recommends that suitable training is provided.

# Organisational impact of topic

The topic discussed by the paper, namely the use of WAFs to manage some of the risks associated with hosting web applications, is relevant to the British Broadcasting Corporation (BBC) and its News website in particular. BBC News receives 28m monthly unique visitors in the UK alone [@dcms] and has a 30% share of Britain's market for online news [@guardian], which makes it a high-profile target for outside attacks. Indeed, BBC web intrastructure has been the subject of numerous distributed denial-of-service (DDoS) attacks over recent years, some of which have caused major outages [@bbc2015a].

The BBC is currently regulated by the BBC Trust, which sets high-level policies and codes for the running of the organisation, including the way that 'key operating risks' are reported and handled by the Executive Board [@bbc2015b]. Any specific policies created around information security need to take into account this supervisory framework, corresponding to the Legislation layer in the policy management hierarchy identified by Hare [-@hare].

## Threat characteristics

Several classes of potential intruder might perceive the BBC website as an appealing target. Although as a public-service broadcaster it does not process payments or other financial information, the organisation's current drive to serve more customised and tailored content online [@bbc2016] entails gathering an increasing amount of personal data about users, which could attract cyber criminals focused on identity theft. Because of its high-profile nature and the perception of it as a trustworthy news source, BBC News could be specifically targeted by 'hacktivist' groups motivated by a social or political cause [@stallings]. Most concerning of all is the risk from highly-skilled Advanced Persistent Threats (APTs) backed by foreign governments, which are reported to be increasingly targeting the UK [@independent]. The Verizon 2016 Data Breach Investigations Report [-@dbir], which Pubal cites a previous version of, shows that public or government targets were the largest victims of recent data breaches attributed to cyber espionage.

Also important in this context is the rise in web applications as an attack vector. The ENISA Threat Landscape report [-@enisa] lists web application attacks as the third-most significant threat, with a 15% increase in prevalence. Similarly the Verizon report [-@dbir] shows that web application attacks are growing across almost all industries, suggesting one reason for this is that web applications may be the only route in to sensitive data in storage. (It also cites input validation as a key recommended control for web applications.) This suggests indicates that web application attacks are a risk in particular need of management.

## Transition to cloud computing (+DevOps?)

Over the past few years the BBC has started migrating some of its online services from a centrally-managed and largely uniform PHP-based application stack running on dedicated, colocated server hardware to a heterogenous cloud-based model in which products such as News and iPlayer have relative freedom to make technology choices that suit their needs. Migrating to the cloud will enable a significant reduction in data centre costs, however the transitional 'hybrid' cloud model currently employed results in an increased network attack surface (Figure \ref{cloud}).

Concomitant with the move to the cloud, the in-house production and management of online services at the BBC is beginning to embrace a 'DevOps' philosophy [@devops] based around the idea of continuous delivery (CD). Where in the past developers wrote software that was then handed over to a dedicated operations team (with a specialised skillset) for deployment into production, these traditional organisational siloes are breaking down, with responsibility for deployment increasingly being shared with developers. This entails developers gaining a deeper understanding of the production environment, including operating system and networking factors, and therefore of the information security issues unique to these domains.

## Stakeholder attitudes and expected responses

This section identifies some of the key stakeholders within BBC News and their relationship to the topic. Here 'stakeholders' is defined as anyone who may be concerned about or affected by the topic, rather than just senior managers. Terms printed in _italics_ are used as per the definitions in RFC4949 [-@rfc4949].

**End users** -- The end users of BBC News services are drawn from the global web audience and have a number of expectations. Surveys show that UK audiences perceive the BBC website as the most trustworthy, accurate and impartial source of news [@dcms]. Any successful _threat action_ that compromises the _data integrity_ of BBC News (for example, through the _falsification_ of news reports, giving rise to _deception_) will have a major impact on user perceptions and therefore public support for the BBC. End users also have an expectation of _availability_, i.e. that BBC News services can be delivered when the users want them. One potential threat action end users would be concerned about would therefore be _obstruction_, with a consequence of _disruption_ to BBC services.

**Web application developers** -- These are responsible for writing the application software behind BBC News online services. They should already be aware of the most critical types of web application weakness, such as the OWASP Top 10 [-@owasp], and be following best practices for avoiding them when writing code. They are now increasingly expected to have a broader range of skills encompassing aspects of 'DevOps', but they may lack experience or confidence in some areas. They alone have a detailed understanding of the internal workings of applications and are able to specify, for example, patterns of valid input that applications should receive. They may be interested in learning more about using WAFs to supplement protections in application code.

**Network administrators** -- Network administrators are expected to be aware of the practical security benefits of WAFs over packet filtering. However they may be concerned about the additional processing overhead of inspecting higher-level protocols and the potential impact on network throughput [@cheswick]. Furthermore, they may have concerns about adding to an already complex set of controls - i.e. yet another set of ingress rules that need to be understood, documented and maintained. They are likely to be particulary interested in the idea of using of WAFs to perform 'virtual patching' on vulnerable systems while developers prepare a permanent fix.

**Information Security officers** -- As Maiwald and Sieglein [-@maiwald] point out, the role of the Information Security department is not to guarantee security, but to help the organisation manage InfoSec risks. Given the BBC's constrained level of funding, these staff would want to evaluate the potential opportunities and costs of using WAFs in the context of the organisation's overall risk appetite. They would be involved in issuing any formal policy or plan around use of WAFs.

**Senior management** -- Managers at the BBC can see the benefit of CD in reducing the time it takes to get a new feature into production, in order to learn more about customer needs and inform the next iteration of development. However they are also most aware of the potential consequences of any harm to the BBC's reputation caused by a loss of service availability or data integrity. They are keen to reduce hosting costs by driving cloud migration but also do not want to increase the level of risk to which the organisation is exposed. They are likely to have a general understanding of the idea of a 'firewall' but not the specific characteristics or benefits of WAFs.

(TODO: add risk assessment - summarised in Scarfone 5-1, risk register; identify assets)

# Example plan

Given the risks identified above, the BBC should implement a security plan around the use of WAFs within its web hosting infrastructure. Firstly, it should identify potential security controls that can help to satisfy security requirements by reducing each risk to acceptable levels [@nist800-53]. These controls can be broadly classified as management, operational or technical [@stallings]. Table \ref{risk-controls} shows some possible controls for one identified risk.

------------------------------------------------------------------------------------------
Control                         Class                   Instance of [@nist800-53]
------------------------------  ----------------------  ----------------------------------
Vulnerability scan cloud        Management              RA-5 Vulnerablilty Scanning
origin servers

Detect and block attacks using  Operational,            SI-3 Malicious Code Protection,
a WAF                           Technical               SC-7 Boundary Protection

Ensure all input validated      Operational             SI-10 Information Input Validation
in application code
------------------------------------------------------------------------------------------

Table: Controls for risk 'Hacker attacks cloud origin server directly' \label{risk-controls}

From this list, a cost-benefit analysis indicates that implementing a control around WAF usage may reduce the likelihood and severity of web application attacks with relatively low implementation cost. Looking again at the security policy hierarchy, we can see that the appropriate layer is a 'standard', since it will include "mandatory activities, actions, rules or regulations" [@hare, p 19]. The use of WAFs is unlikely to be specified directly in the higher ('corporate') policy layer above as it involves too much technical detail for senior management to be able to approve, while specific procedures (the layer below) should be devolved to individual product teams, and a guideline is not appropriate since the use of WAFs should be mandatory

The target audience for the BBC WAF standard will be technical architects, web application developers and network administrators, however the standard will indirectly benefit all staff and end users of BBC products by delivering services that are more resilient to attack. The likely proponent of the standard would be the BBC information security function [@howard].

An outline standard for use of WAFs is given below with some of the key information it should include. A different structure/headings may be adopted for consistency with other BBC information security standards.

## Purpose

The purpose of this standard is to increase the security of BBC web applications being hosted in the cloud by requiring all new applications to incorporate a Web Application Firewall (WAF) into their solution architecture.

## Background

(This section could include the information about the threat landscape described in the previous section.)

## Scope

The standard applies to all new public cloud-hosted web applications regardless of domain (bbc.co.uk, bbc.com), cloud provider (AWS, Google Cloud Platform, etc.) or product (e.g. News, Sport, iPlayer). It does not apply to web applications solely for internal use, or to applications deployed within private cloud platforms.

As this is a new standard, it does not apply to existing web applications that went live before the effective date. Future versions of this standard may include a requirement for WAFs to be used for existing applications.

## Policy

In addition to complying with existing BBC policies [link] around analysis of common web application weaknesses (e.g. OWASP Top 10, CWE/SANS Top 25), it is mandatory for cloud-hosted web applications to be protected against common attacks through the deployment of a WAF or equivalent component.

This standard does not specify the use of a specific WAF product or architecture. However, the following mandatory requirements must be observed:

- The WAF should be 'inline' at all times
- All traffic through the WAF should be logged for auditing purposes
- WAF may be implementated as software-as-a-service (SaaS) or custom instance
- Products must review their WAF using the Web Application Firewall Evaluation Criteria 1.0

## Compliance

The information security department (InfoSec) is responsible for ensuring compliance with this standard and may request evidence from product teams at any time that their WAF is in place and operational. In addition they may perform periodic vulnerability scans to verify that WAF functionality is adequate.

Non-compliance with this standard will be regarded as gross neglience and will be handled through the BBC disciplinary procedure [link].

## Relevant dates

This standard is effective from DD/MM/YYYY. It is due for review after two years, on DD/MM/YYYY.

Other features removed for brevity here but that may be useful in a standard are a glossary, references, a change log [@sanspolicy], and contact details for the author/and or authorising officer [@hare].

# Evaluation of paper

The main strength of the paper is its detailed description of the lab used to demonstrate how a WAF can be deployed within an enterprise and integrate with other tools into a vulnerability scanning and 'virtual patching' workflow. By using the ModSecurity OWASP Core Rule Set (CRS) as initial input, the approach used validates the capabilties of WAFs to detect and mitigate vulnerabilities found in the OWASP Top 10 [-@owasp], which is referenced by standards such as the PCI DSS [-@pcidss] as an example of best practice in vulnerability management. This therefore suggests that WAFs could form part of a 'baseline approach' to implementing generic, industry-standard security controls against common threats [@stallings]. That said, the OWASP Top 10 is currently being revised, having not been updated since 2013, and so the CRS used may need to be updated to reflect any new guidance that emerges.

## Terminology and classification of controls

Pubal states that WAFs can prevent attacks that "network firewalls and intrusion prevention systems cannot" (p.3), but these terms are used flexibly in vendor marketing and there is often overlap betwen the capabilities of each system. WAFs can be seen as a specialised type of application gateway, one of three categories of firewall (along with packet filters and circuit gateways) identified nearly 15 years ago by Cheswick et al. [-@cheswick], but as they point out, the protocol levels analysed by each category is not clear-cut. More recently, Scarfone and Hoffman [-@nist800-41] use a broad application of the term 'firewall' and compare their capabilities by determing which level(s) of the TCP/IP stack the firewall is able to operate on.

Even within the application layer, it may be helpful to distinguish between WAF functionality focused on the HTTP protocol itself and that protecting against weaknesses in web application code. The data sheet for one market-leading WAF [@imperva] shows it "enforces HTTP standards compliance". This is a firewall behaviour termed 'RFC compliance' [@nist800-41] which protects against weaknesses in the protocol implementation (for example, a 'cookie' that does not conform to the standard could be used as an attack against an insecure HTTP parser). By contrast, guidelines such as the OWASP Top 10 normally focus on weaknesses web application that are built on top of HTTP.

Additionally, the 'out-of-band' configuration described in the paper does not strictly fulfil the usual requirement for a firewall that all traffic must past through it [@cheswick].

## Other benefits of WAF controls

Pubal identifies a number of important reasons to consider WAF controls, including detecting and blocking malicious traffic, 'virtual patching' of legacy/COTS software, and their role within a broader network security monitoring infrastructure. However he only briefly mentions their ability to assist with the creation of security audit trails [@rfc4949]. Cheswick et al. [@cheswick] list the ability to log and control all traffic passing through them as a key advantage of the application gateway category of firewall. Scarfone and Hoffman [-@nist800-41] also suggest that application-layer firewalls are able to provide provide user-oriented services such as enforcing authentication or logging events associated with a system user. For example, a suitably-configured WAF could be used to audit failed login attempts for a given user account, which is listed as a security event that should be audited by standards such as X.816 [@x816]. This could be especially useful where a legacy/COTS web application does not provide its own security audit trail. Some high-end commercial WAF products such as BIG-IP [-@f5] even include 'stateful' rules that can automatically detect and block brute-force login attacks by inspecting application traffic, going well beyond the feature set of the example WAF (ModSecurity) discussed in the paper.

The paper focuses on using WAFs for 'shielding' applications in production that have identified weaknesses, without considering the role they have to play in managing web application risk more generally. Implementing multiple, overlapping layers of security is the well-established principle of _defence in depth_, and as [@stallings] point out may address people and operational concerns as well as technology. In the case of the BBC, the need to educate and support web developers in developing more secure applications and for a robust InfoSec review of possible weaknesses does not preclude adding WAFs as a supplementary layer of protection.

Similarly, the inclusion of centralised WAF protection at the edge of the BBC network, through which all traffic would pass (currently under consideration) does not mean that origin servers should not also include WAF components. The use of multiple layers of firewalls is a common way of providing defense-in-depth [@nist800-41], and where different firewall products or configurations are used the software attack surface may be reduced even further. Moreover, the reduced amount of traffic reaching origin servers (due to centralised caching) makes it more practical to apply types of application layer inspection that are more costly in terms of processing time (such as the 'stateful' rules described above) at this level. By contrast the large volume of requests hitting the edge of the network could make such rules cost-prohibitive, application gateways being "poorly suited to high-bandwidth or real-time applications" [@nist800-41, p.2-6].

## Downsides and arguments against WAF usage

From another perspective, WAFs add additional level of complexity to the organisation's infrastructure and increase the maintenance burden on network administrators. As [@nist800-41] point out, having multiple layers of firewalls make debugging problems more difficult, since potentially mutiple sets of logs have to be checked. This problem is made worse in WAFs, since each layer may modify the HTTP messages, and if the WAF is stateful (for example, applies rules based on a sequence of requests) it becomes even more challenging.

There is also the related argument that many of the protections afforded by WAFs (for example, against XSS) are most appropriately enforced in web application code itself, where set of possible valid inputs can be known with certainty and the risk of false positives (where legitimate user behavior is incorrectly identified as malicious) is therefore lowest. At the higher level, the downside of blocking repeated login attempts at the WAF level is that if the WAF is ever bypassed all protection is lost. Protection may also be weakened if a WAF is replaced with an alternate product that employs different heuristics. Web developers typically mitigate such risks using a test-driven development (TDD) approach which makes it easier to spot regressions, but this methodology is not yet widely used for validating WAF behaviour.

Stemming from the above is the human issue that using WAFs could give application developers a false sense of security, believing that they can postpone or limit protections against common weaknesses because a WAF is in-line. Again, should the WAF be bypassed by an attacker, or accidentally disabled, this leave the application unprotected.

A third area which presents challenges for WAF adoption at the BBC is the increasing pressure to encrypt all web traffic using SSL/TLS. Google is one of the main advocates for this trend, tracking SSL adoption across top sites [@google]. By definition WAFs must be able to decrypt such connections in order to inspect the contents, which means that web server SSL certificate(s) must be installed on the WAF system (known as SSL 'offloading'), increasing the complexity of managing certificates across the organisation and enouraging vendor lock-in due to the different approaches handling HTTPS between WAF implementations. Pubal only mentions HTTPS decryption to say that WAFs are more likely to do this than an IPS.

## Implications for cyber security and scope for future work

In the time since the paper was written, organisations such as the BBC have accelerated their transition to cloud hosting. In late 2015 Amazon Web Services (AWS) launched their own Web Application Firewall product [@aws] which has lowered the barriers to adoption through a simple setup process and a pay-as-you-go pricing model (per-rule and per-request). Pubal does refer to a cloud software-as-a-service (SaaS) deployment option for WAFs but does not evaluate any of them in detail. This is a growth area and would a good topic for further investigation.

The concepts of configuration management and infrastructure automation applied to cloud computing have recently come to be closely associated with DevOps [@devops]. Most cloud providers allow architects and developers to define their infrastructure requirements as code, which can be managed and audited through a version control system (VCS). The ability to define WAF rulesets as part of this infrastructure creates an opportunity for web application code to be packaged along with a firewall ruleset tailored to the application by its developers, for automated deployment. This could also be a fruitful area for further research.

# Conclusion

# References
