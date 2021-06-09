# Simple JWT用户指南

## 我应该如何安装？

- 此项目已经被上传到 [Maven中央仓库](https://repo1.maven.org/maven2/cn/vorbote) ，这就意味着 你可以通过向您的`JAVA`项目中的`pom.xml`文件中的`dependencies`
  节点添加如下代码来进行安装：
  ```xml
  <dependency>
    <groupId>cn.vorbote</groupId>
    <artifactId>simple-jwt</artifactId>
    <version>1.0.0</version>
  </dependency>
  ```

- `jar`包将会被上传至`GitHub`，因此您也可以轻松的从GitHub下载这些`jar`包并将它们添加到您的项目依赖库中。但是同时，您的项目中也需要添加如下的文件作为依赖库。
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

## 我应该如何使用？

首先`JwtUtil`和`AccessKeyUtil`使用的完全相同的实现方法，它们之间的区别仅仅体现在其类名称上。 然后，您需要创建它们俩其中任意一个的实例，构造器中包含两个参数，其中一个是您的密钥，还有一个是您（或者您的组织的）名称。

接下来，使用`CreateToken(some params)`方法来创建`Token`,使用`Verify(token)`方法来检查这个生成的`token`，使用`Info(token)`方法来获取`token`中包含的指定数据。