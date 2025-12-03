# Threat Model Document

## Overview

This document contains identified threats for the test application.

## Threats

#### T001 - Authentication

**Priority:** High  
**Category:** Authentication

**Statement:** A malicious attacker with network access can exploit weak authentication mechanisms, which leads to unauthorized system access, resulting in reduced confidentiality of user data.

**Threat Source:** malicious attacker  
**Prerequisites:** network access  
**Threat Action:** exploit weak authentication mechanisms  
**Threat Impact:** unauthorized system access  
**Impacted Goal:** confidentiality  
**Impacted Assets:** user data

#### T002 - Injection

**Priority:** High  
**Category:** Injection

**Statement:** An authorized user with elevated privileges can perform SQL injection attacks, which leads to data exfiltration, resulting in reduced integrity of database records.

**Threat Source:** authorized user  
**Prerequisites:** elevated privileges  
**Threat Action:** perform SQL injection attacks  
**Threat Impact:** data exfiltration  
**Impacted Goal:** integrity  
**Impacted Assets:** database records

#### T003 - Availability

**Priority:** Medium  
**Category:** Availability

**Statement:** A distributed attacker with internet connectivity can launch denial of service attacks, which leads to service unavailability, resulting in reduced availability of application services.

**Threat Source:** distributed attacker  
**Prerequisites:** internet connectivity  
**Threat Action:** launch denial of service attacks  
**Threat Impact:** service unavailability  
**Impacted Goal:** availability  
**Impacted Assets:** application services
