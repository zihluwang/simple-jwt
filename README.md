# Simple JWT User Guide

## How to install?

- This project has been uploaded to [maven central repository](https://repo1.maven.org/maven2/cn/vorbote), which means
  you can add this lib to your `JAVA` project by adding the following codes to `dependencies` node in `pom.xml` file.
  ```xml
  <dependency>
    <groupId>cn.vorbote</groupId>
    <artifactId>simple-jwt</artifactId>
    <version>1.0.0</version>
  </dependency>
  ```

- The `jar` file will be uploaded to GitHub, you can easily download the `jar` file from GitHub and add it to your
  project, but you also need to add the following jar files to your project, because this project need these
  dependencies.
    - `ch.qos.logback:logback-classic:1.2.3`
    - `ch.qos.logback:logback-core:1.2.3`
    - `cn.vorbote:commons:1.5.3`
    - `com.auth0:java-jwt:3.4.0`
    - `com.fasterxml.jackson.core:jackson-annotations:2.9.0`
    - `com.fasterxml.jackson.core:jackson-core:2.9.6`
    - `com.fasterxml.jackson.core:jackson-databind:2.9.6`
    - `commons-codec:commons-codec:1.11`
    - `junit:junit:4.13.1`
    - `org.hamcrest:hamcrest-code:1.3`
    - `org.projectlombok:lombok:1.18.20`
    - `org.slf4j:slf4j-api:1.7.30`

## How to use?

First, `JwtUtil` or `AccessKeyUtil` has the same implementation, and the only difference between them are the name.
Then, you need to create an instance of one of them, the constructor need 2 params which are your secret and
(organization's) name.

After that, use the method `CreateToken(some params)` with needed params to create a token, then use
method `Verify(token)` to check it, use method `Info(token)` to get clear info in this token.