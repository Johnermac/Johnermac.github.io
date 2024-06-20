---
title: "2 - Bloodhound"
classes: single
header:  
  teaser: /assets/images/posts/adx/adx-teaser2.jpg
  overlay_image: /assets/images/main/header1.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Enumeration + Graph Analysis =  Identification of Security Risks"
description: "BloodHound is a versatile and powerful tool for AD enumeration and analysis."
categories:
  - notes
  - adx
tags:
  - beginner
  - AD
  - enum 
toc: true
---

# Bloodhound

> This tool is not only used to enumerate attack paths but also for the defense team to identify areas for improvement in potential security vulnerabilities within the AD

So, basically:
- first u run the a Collector
- bloodhound will collect AD data mostly through LDAP queries (like a regular user would do)
- u'll grab the ZIP file and upload to a local server that will give u analysis and visualization of the AD components via a Graphical Output


> With this Graph u'll be able to visualize attacks paths based on Trusts Relashionships, Poor ACL config, GPO and other stuffs

## Legacy Version

```bash
apt install bloodhound neo4j
neo4j console
go to localhost:7474 and change de password [ default > neo4j:neo4j ]
bloodhound
```

using Covenant:
```bash
shell sharphound.exe -c all = this will capture all domain objects
sharphound saves into a zip file, go ahead and copy the file name
download <bloodhound.zip>
click in the file inside covenant > save file
```

in Bloodhound:
```bash
drag and drop the bloodhound.zip that we got earlier
Database info
Analysis > Find all domain Admins
Analysis > Find Shortest Paths to Domain Admins > click in connection GenericAll > help > abuse info
```

### Collectors
```powershell
- SharpHound = https://github.com/BloodHoundAD/SharpHound
- AzureHound = https://github.com/BloodHoundAD/AzureHound
- Bloodhound.py = https://github.com/fox-it/BloodHound.py
- SilentHound = https://github.com/layer8secure/SilentHound
- RustHound = https://github.com/NH-RED-TEAM/RustHound
```

### Example Collection in Linux

Using Bloodhound.py:
```bash
bloodhound.py -d domain -u user -p 'password' -v --zip -c All -dc 127.0.0.1 --dns-tcp
```

## BloodHound CE 

> CE stand for Community Edition and is the new version. I'll do a step-by-step of how to use it



[Visit BloodHound GitHub Repository](https://github.com/SpecterOps/BloodHound)


[Read about BloodHound Community Edition](https://posts.specterops.io/bloodhound-community-edition-a-new-era-d64689806e90)

[Explore BloodHound SharpHound Documentation](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html)

​Changes:

1. Performance has been improved
2. Bloodhound CE is now accessible in a web version
3. Direct import of ZIP files is no longer supported. You must now load the JSON files
4. This version offers user management + MFA and SAML authentication
5. All actions on the web version are managed through the API. This API can also be used outside of Bloodhound
6. SharpHound has been updated to version 2.0.0

> [IN SUMMARY] The new version is better for teamwork. Cause if more people are involved in the same project, any team member can visualize the results through the web.


​
There is a new version of SharpHound (The collector):

→ https://github.com/BloodHoundAD/SharpHound/releases/tag/v2.0.0

![Alt text](/assets/images/posts/adx/1.png){: .align-center}


Execute the collector on the Target AD

![Alt text](/assets/images/posts/adx/2.png){: .align-center}




### Examples of collection:
```powershell
.\SharpHound.exe --CollectionMethods Session --Loop --Loopduration 02:00:00  --loopinterval 00:10:00​

Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethods All
Invoke-BloodHound -CollectionMethods All -Stealth -OutputDirectory <path>
Invoke-BloodHound -CollectionMethods All -LdapFilter "(physicaldeliveryofficename=...)"
```

All options of **SharpHound** (The collector):

![Alt text](/assets/images/posts/adx/3.png){: .align-center}


### Get the docker-compose.yml file

```yml
# Copyright 2023 Specter Ops, Inc.

version: '3'
services:
  app-db:
    image: docker.io/library/postgres:13.2
    environment:
      - POSTGRES_USER=${POSTGRES_USER:-bloodhound}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-bloodhoundcommunityedition}
      - POSTGRES_DATABASE=${POSTGRES_DATABASE:-bloodhound}
    # Database ports are disabled by default. Please change your database password to something secure before uncommenting
    # ports:
    #   - ${POSTGRES_PORT:-5432}:5432
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "pg_isready -U ${POSTGRES_USER:-bloodhound} -d ${POSTGRES_DATABASE:-bloodhound} -h 127.0.0.1 -p 5432"
        ]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s

  graph-db:
    image: docker.io/library/neo4j:4.4
    environment:
      - NEO4J_AUTH=${NEO4J_AUTH:-neo4j/bloodhoundcommunityedition}
      - NEO4J_dbms_allow__upgrade=${NEO4J_ALLOW_UPGRADE:-true}
    # Database ports are disabled by default. Please change your database password to something secure before uncommenting
    # ports:
    #   - ${NEO4J_DB_PORT:-7687}:7687
    #   - ${NEO4J_WEB_PORT:-7474}:7474
    volumes:
      - ${NEO4J_DATA_MOUNT:-neo4j-data}:/data
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "wget -O /dev/null -q http://localhost:${NEO4J_WEB_PORT:-7474} || exit 1"
        ]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s

  bloodhound:
    image: docker.io/specterops/bloodhound:${BLOODHOUND_TAG:-latest}
    environment:
      - bhe_disable_cypher_qc=${bhe_disable_cypher_qc:-false}
    ports:
      - ${BLOODHOUND_PORT:-8080}:8080
    ### Uncomment to use your own bloodhound.config.json to configure the application
    # volumes:
    #   - ./bloodhound.config.json:/bloodhound.config.json:ro
    depends_on:
      app-db:
        condition: service_healthy
      graph-db:
        condition: service_healthy

volumes:
  neo4j-data:
  postgres-data:


```


[Download BloodHound Docker Compose File](https://raw.githubusercontent.com/SpecterOps/BloodHound/main/examples/docker-compose/docker-compose.yml)

```bash
docker-compose -f docker-compose.yml up
```
or
```
curl -L https://ghst.ly/BHCEDocker | docker compose -f - up
```



### Start the containers


Executing Docker-Compose:

![Alt text](/assets/images/posts/adx/4.png){: .align-center}



Grab the Initial Password:

![Alt text](/assets/images/posts/adx/5.png){: .align-center}



Access the bloodhound in the browser:

http://localhost:8080/ui/login


Change the Initial Password


![Alt text](/assets/images/posts/adx/6.png){: .align-center}


Go to Config - Administration:

![Alt text](/assets/images/posts/adx/7.png){: .align-center}

Upload the JSON Files from the colletor:

![Alt text](/assets/images/posts/adx/8.png){: .align-center}

![Alt text](/assets/images/posts/adx/9.png){: .align-center}

### Results

![Alt text](/assets/images/posts/adx/10.png){: .align-center}

Comparison of bloodhound CE with the Legacy version:

<iframe width="560" height="315" src="https://www.youtube.com/embed/mF63WjXR4FU" frameborder="0" allowfullscreen></iframe>


> its way faster!