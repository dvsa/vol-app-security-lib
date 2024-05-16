# Description
 ZAP Security scan library. This library consists of methods that expose the ZAP JAVA API

# Prerequisites
- Maven

# Building
## Local Deployment
Use the following command ```mvn clean install```

## Remote Deployment
Use the following command ```mvn clean deploy```

## To instantiate use the following 
```ScannerMethods xx = new ScannerMethods();```

## Installation
Add the following Maven dependency to your project's `pom.xml` file:
```xml
<dependency>
    <groupId>org.dvsa.testing.lib</groupId>
    <artifactId>zap-scanner-suite</artifactId>
    <version>LATEST</version>
</dependency>
